"""Offline tests; never runs a privileged command or edits live networking."""
import copy
import contextlib
import importlib
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import guardlib as g
import macos
import toolkit
import admin
import accept
import vps


def options():
    return {'approved': True, 'exit_mode': 'A', 'nodes': ['test-node'], 'expected_exit_country': 'US',
            'expected_exit_ip': '1.1.1.1', 'region_verified': True, 'udp_verified': False,
            'native_on_both_off': False, 'native_on_gui_exit': False, 'replace_global_extension': False,
            'kill_existing_states': True, 'allow_default_pf_reload': False, 'accepted_exceptions': {},
            'domestic_tests': {'urls': ['https://direct-one.example', 'https://direct-two.example'],
                               'ip_url': 'https://exit-test.example', 'expected_ip': '8.8.4.4', 'region_verified': True}}


def source():
    return {'proxies': [{'name': 'test-node', 'type': 'ss', 'server': '192.0.2.20', 'port': 18443,
                         'cipher': 'aes-128-gcm', 'password': 'TEST-ONLY-NOT-A-CREDENTIAL', 'udp': True}],
            'rules': ['MATCH,DIRECT'], 'proxy-groups': [{'name': 'old', 'type': 'fallback', 'proxies': ['DIRECT']}],
            'listeners': [{'type': 'mixed', 'listen': '0.0.0.0', 'port': 12345}]}


class Generation(unittest.TestCase):
    def test_order_no_direct_fallback_and_original_unchanged(self):
        original = source(); before = copy.deepcopy(original)
        config = g.build_config(original, options(), '198.19.0.0/16', 'utun10')
        self.assertEqual(original, before)
        r = config['rules']
        self.assertLess(r.index('GEOSITE,geolocation-!cn,海外出口'), r.index('RULE-SET,guard-direct,DIRECT'))
        self.assertEqual(r[-1], 'MATCH,海外出口')
        self.assertIn('DOMAIN-KEYWORD,mirrorakam', config['rule-providers']['guard-services']['payload'])
        self.assertEqual(config['rule-providers']['guard-services']['payload'], ['DOMAIN-KEYWORD,mirrorakam'])
        for rule in ['GEOSITE,bilibili,DIRECT', 'RULE-SET,guard-wechat,DIRECT,no-resolve']:
            self.assertLess(r.index(rule), r.index('GEOSITE,geolocation-!cn,海外出口'))
        for key in ['geosite:bilibili', 'rule-set:guard-wechat']:
            self.assertEqual(config['dns']['nameserver-policy'][key], ['223.5.5.5#DIRECT', '119.29.29.29#DIRECT'])
        self.assertEqual(config['rule-providers']['guard-wechat']['behavior'], 'classical')
        self.assertEqual(config['rule-providers']['guard-wechat']['interval'], 86400)
        self.assertIn('IP-CIDR,100.64.0.0/10,DIRECT,no-resolve', r)
        self.assertFalse(any('198.19' in x and 'DIRECT' in x for x in r))
        self.assertEqual(config['proxy-groups'], [{'name': '海外出口', 'type': 'select', 'proxies': ['test-node']}])
        self.assertNotIn('listeners', config)

    def test_udp_is_rejected_before_any_overlapping_direct_rule(self):
        c = g.build_config(source(), options(), '198.18.0.0/16', 'utun8')
        self.assertFalse(c['proxies'][0]['udp'])
        for i, rule in enumerate(c['rules']):
            if rule.endswith(',海外出口') and not rule.startswith('MATCH'):
                self.assertTrue(c['rules'][i-1].startswith('AND,((NETWORK,udp),'))
        self.assertEqual(c['rules'][-2], 'NETWORK,udp,REJECT')

    def test_residential_dialer_no_recursion_and_no_udp(self):
        o = options(); o['exit_mode'] = 'B'
        o['residential'] = {'name': 'residential-test', 'type': 'socks5', 'server': '198.51.100.5', 'port': 1080,
                            'username': 'test', 'password': 'TEST-ONLY'}
        c = g.build_config(source(), o, '198.18.0.0/16', 'utun8')
        self.assertEqual(c['proxies'][-1]['dialer-proxy'], '跳板')
        self.assertFalse(c['proxies'][-1]['udp'])
        self.assertEqual(c['proxy-groups'][0]['proxies'], ['residential-test'])
        self.assertEqual(c['proxy-groups'][1]['proxies'], ['test-node'])

    def test_dns_foreign_precedes_domestic(self):
        c = g.build_config(source(), options(), '198.18.0.0/16', 'utun8')
        d = c['dns']; keys = list(d['nameserver-policy'])
        self.assertFalse(d['ipv6'])
        self.assertEqual(d['enhanced-mode'], 'fake-ip')
        self.assertLess(keys.index('geosite:geolocation-!cn'), keys.index('rule-set:guard-direct'))
        self.assertTrue(all(x.endswith('#海外出口') for x in d['nameserver']))
        self.assertEqual(c['rule-providers']['guard-direct']['interval'], 86400)

    def test_conflict_pools_are_not_assumed_free(self):
        self.assertEqual(g.pick_pool(['0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1', '198.18.0.0/16']), '198.19.0.0/16')
        with self.assertRaises(g.GuardError):
            g.pick_pool(['198.18.0.0/15'])
        with self.assertRaises(g.GuardError):
            g.pick_pool(['198.18.5.0/24', '198.19.12.3/32'])

    def test_abbreviated_macos_routes(self):
        self.assertEqual(g.route_networks('198.18 1.2.3.4 UG utun0\n10.48/16 1.2.3.4 UG utun0\ndefault x y\n'),
                         ['198.18.0.0/16', '10.48.0.0/16'])

    def test_invalid_nodes_and_policy_injection_rejected(self):
        for change in [{'type': 'direct'}, {'name': 'DIRECT'}, {'server': 'a,#DIRECT'}, {'port': 0}, {'dialer-proxy': 'old'}]:
            node = copy.deepcopy(source()['proxies'][0]); node.update(change)
            with self.assertRaises(g.GuardError):
                g.validate_node(node)
        with self.assertRaises(g.GuardError):
            g.domains(['example.com,DIRECT'])

    @unittest.skipUnless(shutil.which('node'), 'Node is used only by development tests')
    def test_real_js_refresh_rotates_secret_and_fails_closed(self):
        s = source(); o = options()
        c = g.build_config(s, o, '198.18.0.0/16', 'utun8')
        code = g.extension(c, o)
        def js(value):
            p = subprocess.run([shutil.which('node'), '-e', code + '\nprocess.stdout.write(JSON.stringify(main(JSON.parse(process.argv[1]))));', json.dumps(value)],
                               capture_output=True, text=True, check=True)
            return json.loads(p.stdout)
        self.assertEqual(js(s), c)
        s['proxies'][0]['password'] = 'ROTATED-TEST'
        self.assertEqual(js(s)['proxies'][0]['password'], 'ROTATED-TEST')
        s['proxies'][0]['server'] = '192.0.2.99'
        closed = js(s)
        self.assertEqual(closed['rules'], ['MATCH,REJECT'])
        self.assertEqual(closed['proxy-groups'][0]['proxies'], ['REJECT'])
        self.assertEqual(js(None)['rules'], ['MATCH,REJECT'])


class GuardPolicy(unittest.TestCase):
    def test_four_user_modes_and_faults(self):
        for both, exit_release in itertools.product([False, True], repeat=2):
            decide = lambda gui, t, p, actual, valid=True: g.switch_decision(gui, t, p, actual, valid, both, exit_release)
            self.assertEqual(decide(True, True, True, True), 'guarding')
            self.assertEqual(decide(True, True, False, True), 'guarding')
            self.assertEqual(decide(True, True, True, False), 'restricted')
            self.assertEqual(decide(True, False, True, False), 'restricted')
            self.assertEqual(decide(True, False, False, False), 'native' if both else 'restricted')
            self.assertEqual(decide(False, True, True, True), 'native' if exit_release else 'restricted')
            self.assertEqual(decide(True, False, False, False, False), 'restricted')

    def test_pf_blocks_local_core_bypass_before_loopback(self):
        p = g.render_pf('', [7897, 17997])
        self.assertLess(p.index('clash-guard:local-proxy'), p.index('clash-guard:loopback'))
        self.assertNotIn('pass out quick on utun', p)
        self.assertTrue(p.rstrip().endswith('label "clash-guard:block"'))
        self.assertNotIn('keep state', p)
        self.assertLess(p.index('clash-guard:dns'), p.index('clash-guard:lan4'))
        active = g.render_pf('utun25', [7897])
        self.assertIn('on utun25 all no state', active)
        self.assertNotIn('utun*', active)

    def test_pf_rejects_interface_injection(self):
        with self.assertRaises(g.GuardError):
            g.render_pf('utun0\npass out all', [7897])
        with self.assertRaises(g.GuardError):
            g.render_pf('', ['80'])

    def test_no_unapproved_pf_parent_overwrite(self):
        s = {'options': {'allow_default_pf_reload': True}, 'pf_hashes': {}}
        def fake(args, **kw):
            return subprocess.CompletedProcess(args, 0, 'pass out all\n', '')
        with patch.object(admin, 'run', side_effect=fake) as mock:
            with self.assertRaises(g.GuardError):
                admin.parent_hook(s)
            self.assertFalse(any('-f' in c.args[0] for c in mock.call_args_list))


class Recovery(unittest.TestCase):
    def test_transaction_arms_watchdog_before_mutation_and_rolls_back_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle=Path(tmp); g.dump(bundle/'settings.json',{'id':'fixture'})
            order=[]
            def fail(*args): order.append('mutation'); raise g.GuardError('injected apply failure')
            def recovered(*args,**kwargs): order.append('restore'); return []
            with patch.object(admin,'secure_root'), patch.object(admin,'verify_payload'), patch.object(admin,'check_live'), \
                 patch.object(admin,'configure',side_effect=fail), patch.object(admin,'recover',side_effect=recovered), \
                 patch.object(admin,'run',return_value=subprocess.CompletedProcess([],0,'start-token','')), \
                 patch.object(admin.subprocess,'Popen',side_effect=lambda *a,**k: order.append('watchdog')), \
                 patch.object(admin.signal,'signal'), patch.object(admin,'export_reports'), patch.object(admin,'STORE',bundle), \
                 patch.object(admin.os,'getpgrp',return_value=os.getpid()), patch.object(admin,'quiesce_children'):
                with self.assertRaises(g.GuardError): admin.execute('apply',bundle)
                self.assertEqual(order,['watchdog','mutation','restore'])
                self.assertEqual(g.read_json(bundle/'done-apply')['status'],'rolled_back')
                with self.assertRaises(g.GuardError): admin.execute('apply',bundle)
                self.assertEqual(order,['watchdog','mutation','restore'])

    def test_independent_watchdog_process_survives_parent_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle=Path(tmp); g.dump(bundle/'settings.json',{'id':'fixture'})
            parent=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])
            script = '''import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import admin
admin.STORE = Path(sys.argv[2])
def recover(*args, **kwargs):
    Path(sys.argv[2], "watch-fired").write_text("recovered")
    return []
admin.recover = recover
admin.export_reports = lambda *args: None
admin.watchdog(Path(sys.argv[2]), int(sys.argv[3]), "apply", 10)
'''
            watcher=subprocess.Popen([sys.executable,'-B','-c',script,str(Path(admin.__file__).parent),str(bundle),str(parent.pid)],
                                     start_new_session=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                parent.terminate(); parent.wait(3)
                out,err=watcher.communicate(timeout=8)
                self.assertEqual(watcher.returncode,0,err.decode())
                self.assertEqual((bundle/'watch-fired').read_text(),'recovered')
                self.assertEqual(g.read_json(bundle/'done-apply')['status'],'watchdog_rollback')
            finally:
                if parent.poll() is None: parent.kill(); parent.wait()
                if watcher.poll() is None: watcher.kill(); watcher.wait()

    def test_restore_does_not_short_circuit(self):
        seen = []
        def fail():
            seen.append('failed'); raise ValueError('injected')
        errors = g.restore_steps([('a', fail), ('b', lambda: seen.append('restored')), ('c', fail)], lambda m: None)
        self.assertEqual(seen, ['failed', 'restored', 'failed'])
        self.assertEqual(len(errors), 2)

    def test_network_restore_attempts_each_setting_after_failure(self):
        network = {'Wi-Fi test': {'dns': [], 'http': {'Enabled': 'No'}, 'https': {'Enabled': 'No'},
                                 'socks': {'Enabled': 'No'}, 'pac': {'Enabled': 'No'}}}
        called = []
        def fake(argv, **kw):
            called.append(argv)
            if '-setdnsservers' in argv: raise g.GuardError('injected DNS error')
            return subprocess.CompletedProcess(argv, 0, '', '')
        with patch.object(macos, 'run', side_effect=fake):
            with self.assertRaises(g.GuardError): macos.restore_network(network, lambda m: None)
        self.assertEqual(len(called), 5)
        self.assertIn('-setautoproxystate', called[-1])

    def test_snapshot_manifest_detects_tampering_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); (p/'a').write_text('a')
            before = g.manifest(p)
            (p/'a').write_text('changed')
            self.assertNotEqual(g.manifest(p), before)
            (p/'link').symlink_to(p/'a')
            with self.assertRaises(g.GuardError): g.manifest(p)

    def test_atomic_files_private_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'private'
            g.atomic(p, 'secret')
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            q = Path(tmp)/'link'; q.symlink_to(p)
            with self.assertRaises(g.GuardError): g.atomic(q, 'bad')
            self.assertEqual(p.read_text(), 'secret')

    def test_watchdog_recovers_after_parent_is_gone(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp)
            g.dump(bundle/'settings.json', {'id':'fixture'})
            seen = []
            with patch.object(admin.os, 'kill', side_effect=ProcessLookupError), \
                 patch.object(admin, 'recover', side_effect=lambda *a, **k: seen.append('recovered') or []), \
                 patch.object(admin, 'export_reports'), patch.object(admin,'STORE',bundle), patch.object(admin,'terminate_group'):
                admin.watchdog(bundle, 123, 'apply', 1)
            self.assertEqual(seen, ['recovered'])
            self.assertEqual(g.read_json(bundle/'done-apply')['status'], 'watchdog_rollback')

    def test_failed_recovery_copy_preserves_complete_live_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); live=root/'config'; live.mkdir(); (live/'important').write_text('live intact')
            snapshot=root/'snapshot'; (snapshot/'config').mkdir(parents=True)
            def partial(src,dst):
                Path(dst).mkdir(); (Path(dst)/'partial').write_text('half copy')
                raise OSError('injected disk-full')
            with patch.object(macos.shutil,'copytree',side_effect=partial):
                with self.assertRaises(OSError):
                    macos.restore_config(snapshot,{'config_dir':str(live),'uid':os.getuid(),'gid':os.getgid()})
            self.assertEqual((live/'important').read_text(),'live intact')
            self.assertFalse((live/'partial').exists())

    def test_failed_new_guard_is_removed_but_old_guard_restarts_restricted(self):
        for preserved in [False, True]:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); guard=root/'guard'; guard.mkdir(); snap=root/'snapshot'; snap.mkdir()
                g.dump(guard/'settings.json',{'id':'fixture'})
                g.dump(snap/'state.json',{'gui_running':False}); g.dump(snap/'network.json',{})
                if preserved:
                    (snap/'guard-present').write_text('yes'); (snap/'guard.plist').write_bytes(b'plist')
                calls=[]
                def run(argv,**kw):
                    calls.append(argv)
                    return subprocess.CompletedProcess(argv,1 if 'print' in argv else 0,'','')
                def off(s,remove=False):
                    calls.append(['off',remove])
                    if remove: shutil.rmtree(guard)
                with patch.object(admin,'GUARD',guard), patch.object(admin,'LAUNCH',root/'guard.plist'), \
                     patch.object(admin,'secure_root'), patch.object(admin,'run',side_effect=run), \
                     patch.object(admin,'off',side_effect=off), patch.object(admin,'load_pf',side_effect=lambda s,t:calls.append(['pf',t])), \
                     patch.object(admin,'stop_gui'),patch.object(admin,'api',side_effect=g.GuardError('TUN down')), \
                     patch.object(admin,'restore_config'),patch.object(admin,'restore_network'),patch.object(admin,'check_guard'), \
                     patch.object(admin,'log'):
                    errors=admin.recover({'id':'fixture'},snap,root,original=False)
                self.assertEqual(errors,[])
                if preserved:
                    self.assertTrue(guard.exists())
                    self.assertTrue((guard/'hold-restricted').exists())
                    self.assertIn(['pf',''],calls)
                    self.assertTrue(any('bootstrap' in c for c in calls))
                    self.assertNotIn(['off',False],calls)
                else:
                    self.assertFalse(guard.exists())
                    self.assertIn(['off',True],calls)

    def test_watchdog_stops_late_mutating_child_before_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle=Path(tmp); g.dump(bundle/'settings.json',{'id':'fixture'})
            state=bundle/'state'; state.write_text('initial')
            child="import time; from pathlib import Path; time.sleep(4); Path(%r).write_text('late mutation')" % str(state)
            parent_code="import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',%r]); time.sleep(30)" % child
            parent=subprocess.Popen([sys.executable,'-c',parent_code],start_new_session=True)
            time.sleep(.2)
            script='''import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import admin
admin.STORE=Path(sys.argv[2])
def restore(*args,**kwargs):
    Path(sys.argv[2],'state').write_text('restored')
    return []
admin.recover=restore
admin.export_reports=lambda *a: None
admin.watchdog(Path(sys.argv[2]),int(sys.argv[3]),'apply',10)
'''
            watcher=subprocess.Popen([sys.executable,'-B','-c',script,str(Path(admin.__file__).parent),str(bundle),str(parent.pid)],
                                     start_new_session=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                parent.terminate();parent.wait(3)
                out,err=watcher.communicate(timeout=10)
                self.assertEqual(watcher.returncode,0,err.decode())
                time.sleep(4)
                self.assertEqual(state.read_text(),'restored')
            finally:
                if parent.poll() is None: parent.kill();parent.wait()
                if watcher.poll() is None: watcher.kill();watcher.wait()

    def test_committed_transaction_is_not_rolled_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle=Path(tmp); g.atomic(bundle/'done-apply','{}')
            with patch.object(admin, 'recover') as recover:
                admin.watchdog(bundle, 123, 'apply', 1)
                recover.assert_not_called()


class Preflight(unittest.TestCase):
    def test_domestic_targets_required_and_validated_before_prepare(self):
        mutations = [None, {}, {'urls': []}, {'urls': ['https://direct-one.example']},
                     {'urls': ['https://direct-one.example/a', 'https://direct-one.example/b']},
                     {'ip_url': 'https://user:secret@exit-test.example'}, {'ip_url': 'https://127.0.0.1'},
                     {'ip_url': 'https://site.local'}, {'ip_url': 'https://exit-test.example?secret=value'},
                     {'ip_url': 'https://exit-test.example#section'}, {'ip_url': 'https://exit-test.example:bad'},
                     {'expected_ip': '192.0.2.1'}, {'expected_ip': '1.1.1.1'}, {'expected_ip': 'not-an-ip'},
                     {'region_verified': False}]
        for change in mutations:
            with self.subTest(change=change):
                o = options()
                if change is None:
                    del o['domestic_tests']
                elif not change:
                    o['domestic_tests'] = {}
                else:
                    o['domestic_tests'].update(change)
                with self.assertRaises(g.GuardError):
                    toolkit.check_options(o)

    def test_missing_domestic_targets_cannot_pass_acceptance_or_start_drills(self):
        s = {'uid': 501, 'options': {}}
        with patch.object(accept, 'api') as api, patch.object(accept, 'curl_probe') as probe:
            report = accept.network_acceptance(s, Path('/unused'))
            self.assertFalse(report['gate_passed'])
            self.assertEqual(report['items']['3']['status'], 'fail')
            with self.assertRaises(g.GuardError):
                accept.drills(s, Path('/unused'))
            api.assert_not_called()
            probe.assert_not_called()

    def test_domestic_acceptance_requires_direct_logs_success_and_exact_native_ip(self):
        for ip, route, code, reachable, expected in [('8.8.4.4', True, 200, True, 'pass'),
                ('1.1.1.1', True, 200, True, 'fail'), ('8.8.8.8', True, 200, True, 'fail'),
                ('8.8.4.4', False, 200, True, 'fail'), ('8.8.4.4', True, 403, True, 'fail'),
                ('8.8.4.4', True, 200, False, 'fail')]:
            o = options(); s = {'uid': 501, 'options': o}
            trace = types.SimpleNamespace(lines=[], route=lambda *a: ['DIRECT'] if route else [])
            def response(settings, url):
                return {'url': url, 'reachable': reachable, 'http': code, 'ip': ip if url == o['domestic_tests']['ip_url'] else ''}
            with patch.object(accept, 'curl_probe', side_effect=response) as probe, patch.object(accept.time, 'sleep'):
                result = accept.direct_acceptance(s, trace)
                self.assertEqual(result['status'], expected)
                self.assertEqual([c.args[1] for c in probe.call_args_list], o['domestic_tests']['urls'] + [o['domestic_tests']['ip_url']])

    def test_ip_probe_does_not_guess_addresses_from_page_text(self):
        s = {'uid': 501, 'mixed_port': 7897}
        for body, expected in [('8.8.4.4', '8.8.4.4'), ('{"ip":"8.8.4.4"}', '8.8.4.4'),
                               ('A page mentioning 8.8.4.4', '')]:
            output = subprocess.CompletedProcess([], 0, body + '\n__GUARD__200 198.18.0.9 0.5', '')
            with patch.object(macos, 'user_run', return_value=output):
                self.assertEqual(macos.curl_probe(s, 'https://exit-test.example')['ip'], expected)

    def test_pf_hit_counters_required_for_block_evidence(self):
        text='@0 block drop out quick all label "clash-guard:block"\n [ Evaluations: 8 Packets: 3 Bytes: 120 States: 0 ]\n@1 pass out all label "other"\n [ Evaluations: 9 Packets: 100 Bytes: 1000 States: 0 ]\n'
        self.assertEqual(accept.blocked_packets(text),3)
        self.assertEqual(accept.blocked_packets(''),0)

    def test_explicit_choices_and_country(self):
        toolkit.check_options(options())
        for key, value in [('approved', False), ('native_on_gui_exit', None), ('expected_exit_country', 'HK'),
                           ('region_verified', False), ('kill_existing_states', False)]:
            o=options(); o[key]=value
            with self.assertRaises((g.GuardError, ValueError)): toolkit.check_options(o)

    def test_only_named_accepted_exceptions(self):
        o=options(); o['accepted_exceptions']={'anything': 'pretend passed'}
        with self.assertRaises(g.GuardError): toolkit.check_options(o)

    def test_empty_commented_extension_is_handled(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'script.js'; p.write_text('// note\nfunction main(config, profile) { return config; }')
            self.assertTrue(toolkit.empty_extension(p))
            p.write_text('function main(config) { config.rules=[]; return config; }')
            self.assertFalse(toolkit.empty_extension(p))
            p=Path(tmp)/'merge.yaml'; p.write_text('# comment only\n')
            self.assertTrue(toolkit.empty_extension(p))

    def test_shell_entries_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            for action in ['apply','guard','drill','restore']:
                p=Path(tmp)/(action+'.sh'); p.write_text(toolkit.shell_entry(action))
                subprocess.run(['/bin/sh','-n',str(p)],check=True)

    def test_normal_user_curl_ignores_proxy_configuration(self):
        s={'uid':501,'user':'fixture','home':'/tmp/fixture','mixed_port':7897}
        output=subprocess.CompletedProcess([],0,'1.1.1.1\n__GUARD__200 198.18.0.9 0.5','')
        with patch.object(macos,'user_run',return_value=output) as mock:
            p=macos.curl_probe(s,'https://api.ipify.org')
        argv=mock.call_args.args[1]
        self.assertEqual(argv[:2],['/usr/bin/curl','-q'])
        self.assertIn('--noproxy',argv)
        self.assertEqual(argv[argv.index('--noproxy')+1],'*')
        self.assertNotIn('--proxy',argv)
        self.assertEqual(p['uid'],501)
        self.assertEqual(p['ip'],'1.1.1.1')

    def test_no_dns_timeout_false_firewall_pass(self):
        with patch.object(accept,'curl_probe',return_value={'exit':6,'reachable':False}):
            _, okay=accept.blocked_probes({})
        self.assertFalse(okay)

    def test_complete_prepare_builds_offline_bundle_without_live_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp)/'home'; home.mkdir(); (home/'Desktop').mkdir()
            cfg=home/'Library/Application Support'/macos.CLIENT_ID
            (cfg/'profiles').mkdir(parents=True)
            g.dump(cfg/'profiles.yaml',{'current':'local','items':[
                {'uid':'Merge','type':'merge','file':'Merge.yaml'}, {'uid':'Script','type':'script','file':'Script.js'},
                {'uid':'local','type':'local','file':'local.yaml'}]})
            g.dump(cfg/'profiles/Merge.yaml',{})
            (cfg/'profiles/Script.js').write_text('function main(config) { return config; }')
            g.dump(cfg/'profiles/local.yaml',source())
            g.dump(cfg/'verge.yaml',{'enable_tun_mode':False,'enable_system_proxy':True,'enable_auto_launch':False,'verge_mixed_port':17997})
            g.dump(cfg/'config.yaml',{'mixed-port':17997,'tun':{'enable':False}})
            app=home/'Applications/Clash Verge.app'; core=app/'Contents/MacOS/verge-mihomo'
            core.parent.mkdir(parents=True); core.write_text('fixture'); core.chmod(0o700)
            network={'Wi-Fi Fixture':{'dns':[],'http':{'Enabled':'No'},'https':{'Enabled':'No'},'socks':{'Enabled':'No'},'pac':{'Enabled':'No'}}}
            report={'clients':[{'supported':True,'app':str(app),'executable':str(core.parent/'clash-verge'),'version':'2.5.10'}],
                'commands':{'/bin/sh':True},'existing_guard':False,'conflicts':[],'config_dir':str(cfg),
                'runtime':{'mixed-port':17997},'network':network,'route_networks':[],'interfaces':[],
                'service_present':True,'api_socket':str(home/'test.sock')}
            identity=types.SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid(),pw_name='fixture',pw_dir=str(home))
            inject_edit = [False]
            def resources(stage, config, port):
                (stage/'ruleset').mkdir()
                g.dump(stage/'ruleset/guard-direct.yaml',{'payload':['+.example.com']})
                (stage/'geosite.dat').write_bytes(b'x'*12000)
                if inject_edit[0]:
                    value=g.read_json(cfg/'config.yaml'); value['external-user-edit']=True
                    g.dump(cfg/'config.yaml',value)
                return {'fixture':True}
            before=g.manifest(cfg)
            opts=home/'options.json'; g.dump(opts,options())
            output=home/'clash-guard-backup/fixture'
            def okay(argv,**kw): return subprocess.CompletedProcess(argv,0,'fixture preflight','')
            with patch.object(toolkit,'discover',return_value=report), patch.object(toolkit,'api',return_value={'delay':50}), \
                 patch.object(toolkit,'run',side_effect=okay), patch.object(toolkit,'download_rules',side_effect=resources), \
                 patch.object(toolkit.pwd,'getpwuid',return_value=identity), patch.object(Path,'home',return_value=home), \
                 patch.object(toolkit,'gui_processes',return_value=[]), patch.object(macos,'gui_processes',return_value=[]), \
                 patch.object(macos,'network_snapshot',return_value=network):
                result=toolkit.prepare(opts,output)
                self.assertEqual(g.manifest(cfg),before)
                nodefile=home/'node.json'; g.dump(nodefile,source()['proxies'][0])
                g.atomic(home/'COMMITTED','fixture committed')
                evidence=home/'node-evidence.json'; g.dump(evidence,{'passed':True,'node_sha256':g.sha(nodefile)})
                imported=home/'clash-guard-backup/imported'
                with patch.object(vps,'probe',return_value={'ip':'1.1.1.1','country':'US'}), \
                     patch.object(vps,'isolated_proxy',return_value=contextlib.nullcontext(17999)), \
                     patch.object(toolkit,'curl_probe',return_value={'reachable':False}):
                    toolkit.prepare(opts,imported,nodefile,evidence)
                self.assertEqual(g.manifest(cfg),before)
                imported_settings=g.read_json(imported/'settings.json')
                self.assertTrue(imported_settings['import_profile'])
                self.assertEqual(imported_settings['original_health']['native_url'], options()['domestic_tests']['urls'][0])
                self.assertEqual(g.read_json(imported/'stage/profiles.yaml')['items'][:3], g.read_json(cfg/'profiles.yaml')['items'])
                self.assertEqual(g.read_json(imported/'stage/node-profile.yaml')['proxies'],source()['proxies'])
                admin.verify_payload(imported)
                inject_edit[0]=True
                drift=home/'clash-guard-backup/drift'
                with self.assertRaises(g.GuardError): toolkit.prepare(opts,drift)
                self.assertFalse((drift/'PREPARED').exists())
                self.assertTrue(g.read_json(cfg/'config.yaml')['external-user-edit'])
            self.assertFalse(result['changed_live_network'])
            self.assertTrue((output/'original/COMPLETE').exists())
            for name in ['apply.sh','install-guard.sh','drill.sh','restore.sh','PREPARED']:
                self.assertTrue((output/name).is_file(),name)
            admin.verify_payload(output)
            self.assertIn(str(imported/'restore.sh'),(home/'Desktop/断网急救.txt').read_text())
            g.atomic(output/'stage/Script.js','tampered')
            with self.assertRaises(g.GuardError): admin.verify_payload(output)

    def test_dns_leak_api_schema_and_chinese_resolver_are_not_accepted(self):
        def response(value): return subprocess.CompletedProcess([],0,json.dumps(value),'')
        for servers, okay in [([{'ip_address':'1.1.1.1','country_code':'US'}],True),
                              ([{'ip_address':'223.5.5.5','country_code':'CN'}],False),
                              ([{'ip_address':'1.1.1.1','country_code':'unknown'}],False),([],False)]:
            with patch.object(accept,'user_run',side_effect=[response({'status':200}),response({'count':len(servers)}),response(servers)]), \
                 patch.object(accept,'curl_probe',return_value={'exit':60}):
                value=accept.dns_leak_scan({})
            self.assertEqual(value['pass'],okay)


if __name__ == '__main__':
    unittest.main(verbosity=2)
