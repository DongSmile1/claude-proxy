"""Offline VPS transaction/import tests. Never connects to SSH or runs privileged commands."""
import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import vps
import vps_remote as remote
import guardlib as g
import toolkit
import admin
import macos


def plan():
    return {'id': 'a' * 24, 'port': 18443, 'password': base64.b64encode(b'0123456789abcdef').decode(),
            'release': {'tag': 'v26.1.1', 'asset': 'Xray-linux-64.zip', 'sha256': '1' * 64,
                        'url': 'https://github.com/XTLS/Xray-core/releases/download/v26.1.1/Xray-linux-64.zip'},
            'baseline': {'firewall': {'mode': 'none'}}, 'approved': True}


class VPS(unittest.TestCase):
    def test_server_uses_authenticated_tcp_and_explicitly_blocks_udp_private_ips(self):
        p = plan(); remote.validate_plan(p)
        config = remote.config(p)
        self.assertEqual(config['inbounds'][0]['settings']['password'], p['password'])
        self.assertEqual(config['inbounds'][0]['settings']['network'], 'tcp')
        self.assertEqual(config['routing']['rules'][0]['network'], 'udp')
        self.assertIn('100.64.0.0/10', config['routing']['rules'][1]['ip'])
        self.assertIn('::/0', config['routing']['rules'][1]['ip'])
        self.assertIn('DynamicUser=yes', remote.service_text())
        self.assertIn('LoadCredential=', remote.service_text())

    def test_plan_refuses_unsigned_assets_injection_and_invalid_credentials(self):
        for field, value in [('id', '../bad'), ('port', 22), ('password', 'not-a-key'), ('approved', False)]:
            p = plan(); p[field] = value
            with self.assertRaises(Exception): remote.validate_plan(p)
        for field, value in [('url', 'https://evil.invalid/xray.zip'), ('sha256', ''), ('tag', 'v1;id')]:
            p = plan(); p['release'][field] = value
            with self.assertRaises(Exception): remote.validate_plan(p)

    def test_release_pins_official_asset_digest(self):
        p = plan()['release']
        data = {'tag_name': p['tag'], 'assets': [{'name': p['asset'], 'browser_download_url': p['url'], 'digest': 'sha256:' + p['sha256']}]}
        with patch.object(remote, 'fetch', return_value=json.dumps(data).encode()):
            self.assertEqual(remote.release('x86_64'), p)
        data['assets'][0]['browser_download_url'] = 'https://elsewhere.invalid/file'
        with patch.object(remote, 'fetch', return_value=json.dumps(data).encode()):
            with self.assertRaises(RuntimeError): remote.release('x86_64')

    def test_unknown_firewall_never_assumed_open(self):
        def executable(name): return '/usr/sbin/' + name if name in ['nft', 'iptables-save'] else None
        with patch.object(remote.shutil, 'which', side_effect=executable), patch.object(remote, 'call', return_value=subprocess.CompletedProcess([], 0, 'table inet custom {}', '')):
            with self.assertRaises(RuntimeError): remote.firewall(18443)

    def test_passwords_not_in_ssh_argv_and_host_key_checks_preserved(self):
        settings = {'control': '/tmp/private/ctl', 'host': '192.0.2.10', 'user': 'admin', 'ssh_port': 2222}
        with patch.object(vps, 'interactive') as call:
            vps.remote(settings, ['/usr/bin/python3', '/tmp/path with space.py', 'inspect'], True)
        argv = call.call_args.args[0]
        self.assertIn('StrictHostKeyChecking=ask', argv)
        self.assertNotIn('StrictHostKeyChecking=no', argv)
        self.assertEqual(argv[-1], "sudo -- /usr/bin/python3 '/tmp/path with space.py' inspect")
        self.assertNotIn('password', ' '.join(argv).lower())

    def test_local_init_is_private_and_has_no_ssh_side_effect(self):
        with tempfile.TemporaryDirectory() as d, patch.object(vps, 'remote') as ssh:
            b = Path(d) / 'batch'
            result = vps.init('1.1.1.1', 22, 'root', 18443, 'TEST-NODE', b)
            ssh.assert_not_called()
            self.assertFalse(result['live_changes'])
            self.assertEqual(b.stat().st_mode & 0o777, 0o700)
            self.assertFalse((b / 'node.json').exists())
            for name in ['connect-and-inspect.sh', 'deploy-node.sh', 'restore-node.sh']:
                subprocess.run(['/bin/sh', '-n', b / name], check=True)
            control = Path(g.read_json(b / 'ssh.json')['control']).parent
            control.rmdir()

    def test_recovery_attempts_later_steps_after_failure_and_never_touches_ssh(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); b = root / ('a' * 24); b.mkdir()
            units = root / 'units'; units.mkdir(); install = root / 'node'; install.mkdir()
            (units / remote.UNIT).write_text('owned'); (b / 'MUTATING').write_text('owned')
            g.dump(b / 'plan.json', plan()); g.dump(b / 'status.json', {'phase': 'ready'})
            g.dump(root / 'current.json', {'id': 'a' * 24})
            calls = []
            def call(args, check=True, **kw):
                calls.append(list(map(str, args)))
                if args[:3] == ['systemctl', 'disable', '--now'] and args[-1] == remote.UNIT:
                    raise RuntimeError('injected disable failure')
                return subprocess.CompletedProcess(args, 0, 'inactive\n', '')
            with patch.object(remote, 'ROOT', root), patch.object(remote, 'UNITS', units), patch.object(remote, 'INSTALL', install), \
                 patch.object(remote, 'private_root'), patch.object(remote, 'call', side_effect=call):
                with self.assertRaises(RuntimeError): remote.restore('a' * 24)
            self.assertFalse(install.exists())
            self.assertIn(['systemctl', 'daemon-reload'], calls)
            self.assertEqual(g.read_json(b / 'status.json')['phase'], 'restore_failed')
            self.assertFalse(any('ssh' in ' '.join(c) or '-F' in c for c in calls))

    def test_lease_does_not_undo_committed_node(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); b = root / ('a' * 24); b.mkdir(); g.dump(b / 'status.json', {'phase': 'committed'})
            with patch.object(remote, 'ROOT', root), patch.object(remote, 'private_root'), patch.object(remote, 'call') as call:
                remote.restore('a' * 24, lease=True)
                call.assert_not_called()

    def test_expired_lease_cannot_commit(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); b = root / ('a' * 24); b.mkdir(); g.dump(b / 'plan.json', plan())
            g.dump(b / 'status.json', {'phase': 'ready', 'deadline': time.time() - 1})
            with patch.object(remote, 'ROOT', root), patch.object(remote, 'private_root'), patch.object(remote, 'call') as call:
                with self.assertRaises(RuntimeError): remote.commit('a' * 24)
                call.assert_not_called()

    def test_listener_must_belong_to_this_service_pid(self):
        def commands(args, check=True, **kw):
            out = '111\n' if 'MainPID' in args else 'LISTEN 0 10 0.0.0.0:18443 0.0.0.0:* users:(("xray",pid=222,fd=3))\n'
            return subprocess.CompletedProcess(args, 0, out, '')
        with patch.object(remote, 'call', side_effect=commands), patch.object(remote.time, 'sleep'), \
             patch.object(remote.time, 'monotonic', side_effect=[0, 1, 22]):
            with self.assertRaises(RuntimeError): remote.verify_service(plan())

    def test_invalid_archive_checksum_fails_before_any_live_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); b = root / ('a' * 24); b.mkdir(); p = plan()
            g.dump(b / 'plan.json', p); g.dump(b / 'status.json', {'phase': 'prepared', 'deadline': time.time() + 900})
            g.dump(root / 'current.json', {'id': 'a' * 24})
            (b / 'COMPLETE').write_text('done')
            with patch.object(remote, 'ROOT', root), patch.object(remote, 'private_root'), patch.object(remote, 'inspect', return_value=p['baseline']), \
                 patch.object(remote, 'fetch', return_value=b'wrong'), patch.object(remote, 'call') as call:
                with self.assertRaises(RuntimeError): remote.apply('a' * 24)
                call.assert_not_called()
            self.assertFalse((b / 'MUTATING').exists())
            self.assertEqual(g.read_json(b / 'status.json')['phase'], 'failed')

    def test_old_restore_cannot_remove_a_new_node(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); b = root / ('a' * 24); b.mkdir()
            g.dump(root / 'current.json', {'id': 'b' * 24})
            with patch.object(remote, 'ROOT', root), patch.object(remote, 'private_root'), patch.object(remote, 'call') as call:
                g.dump(b / 'status.json', {'phase': 'restored'})
                remote.restore('a' * 24)
                g.dump(b / 'status.json', {'phase': 'restore_failed'})
                with self.assertRaises(RuntimeError): remote.restore('a' * 24)
                call.assert_not_called()

    def test_timer_survives_reboot_without_expired_boot_relative_trigger(self):
        text = remote.timer_text('a' * 24, 1794900000)
        self.assertIn('OnCalendar=', text)
        self.assertIn(' UTC', text)
        self.assertIn('Persistent=true', text)
        self.assertNotIn('OnBootSec', text)

    def test_desktop_wrong_guard_owner_fails_before_any_recovery_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); guard = root / 'guard'; guard.mkdir()
            g.dump(guard / 'settings.json', {'id': 'new'})
            with patch.object(admin, 'GUARD', guard), patch.object(admin, 'secure_root'), \
                 patch.object(admin, 'stop_gui') as stop, patch.object(admin, 'restore_network') as network:
                with self.assertRaises(g.GuardError): admin.recover({'id': 'old'}, root / 'absent-snapshot', root, original=True)
                stop.assert_not_called(); network.assert_not_called()

    def test_first_import_restore_uses_native_baseline_not_unavailable_claude(self):
        settings = {'mixed_port': 7897, 'original_health': {'native': True, 'native_url': 'https://direct-one.example', 'proxy_claude': False}}
        with patch.object(macos.socket, 'create_connection', return_value=contextlib.nullcontext()), \
             patch.object(macos, 'curl_probe', return_value={'reachable': True}) as probe:
            result = macos.baseline_health(settings)
            self.assertTrue(result['external_verified'])
            self.assertEqual(probe.call_args.args[1], settings['original_health']['native_url'])
            self.assertNotIn('explicit_proxy', probe.call_args.kwargs)

    def test_bootstrap_arms_recovery_before_launching_detached_job(self):
        id = os.urandom(12).hex()
        upload = Path('/tmp/proxy-guard-' + id); upload.mkdir(mode=0o700)
        try:
            with tempfile.TemporaryDirectory() as d:
                root = Path(d) / 'backups'; units = Path(d) / 'units'; units.mkdir()
                engine = Path(remote.__file__).read_text(); (upload / 'vps_remote.py').write_text(engine)
                p = plan(); p['id'] = id; p['engine_sha256'] = g.sha(upload / 'vps_remote.py'); g.dump(upload / 'plan.json', p)
                commands = []
                def call(args, check=True, **kw):
                    commands.append(list(map(str, args)))
                    self.assertTrue((root / id / 'COMPLETE').exists())
                    return subprocess.CompletedProcess(args, 0, '', '')
                with patch.object(remote, 'ROOT', root), patch.object(remote, 'UNITS', units), patch.object(remote, 'private_root'), \
                     patch.object(remote, 'inspect', return_value=p['baseline']), patch.object(remote, 'call', side_effect=call):
                    remote.bootstrap(upload)
                enable = next(i for i, c in enumerate(commands) if c[:3] == ['systemctl', 'enable', '--now'])
                launch = next(i for i, c in enumerate(commands) if c[0] == 'systemd-run')
                self.assertLess(enable, launch)
                self.assertIn('--property=TimeoutStartSec=600', commands[launch])
                self.assertIn('--property=KillMode=control-group', commands[launch])
                self.assertEqual(g.read_json(root / 'current.json')['id'], id)
                self.assertTrue((root / id / 'restore.sh').exists())
        finally:
            import shutil
            shutil.rmtree(upload)

    def test_new_profile_preserves_old_subscription_metadata_and_bytes(self):
        profiles = {'current': 'old', 'items': [{'uid': 'old', 'type': 'remote', 'file': 'old.yaml', 'url': 'PRIVATE'}]}
        before = copy.deepcopy(profiles)
        node = {'name': 'vps-fixture', 'type': 'ss', 'server': '192.0.2.20', 'port': 18443, 'password': 'TEST'}
        result, selected, source = toolkit.imported_profile(profiles, node)
        self.assertEqual(profiles, before)
        self.assertEqual(result['items'][0], before['items'][0])
        self.assertNotEqual(result['current'], before['current'])
        self.assertEqual(source['proxies'], [node])
        with tempfile.TemporaryDirectory() as d:
            b = Path(d); cfg = b / 'cfg'; (cfg / 'profiles').mkdir(parents=True)
            old = cfg / 'profiles/old.yaml'; old.write_text('original bytes')
            new = cfg / 'profiles' / selected['file']; g.dump(new, source)
            g.dump(b / 'expected-live.json', {'profiles/old.yaml': g.sha(old)})
            s = {'config_dir': str(cfg), 'subscription': 'profiles/' + selected['file'], 'import_profile': True,
                 'subscription_sha256': g.sha(new), 'script_file': 'profiles/Script.js', 'merge_file': 'profiles/Merge.yaml'}
            g.verify_subscription_files(s, b)
            old.write_text('changed')
            with self.assertRaises(g.GuardError): g.verify_subscription_files(s, b)

    def test_empty_current_allowed_only_for_new_import(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d); (cfg / 'profiles').mkdir()
            g.dump(cfg / 'profiles.yaml', {'current': None, 'items': [{'uid': 'Merge', 'type': 'merge', 'file': 'Merge.yaml'}, {'uid': 'Script', 'type': 'script', 'file': 'Script.js'}]})
            g.dump(cfg / 'profiles/Merge.yaml', {}); (cfg / 'profiles/Script.js').write_text('// empty')
            with self.assertRaises(g.GuardError): toolkit.profile_details(cfg)
            self.assertIsNone(toolkit.profile_details(cfg, allow_empty_current=True)[1])


if __name__ == '__main__':
    unittest.main()
