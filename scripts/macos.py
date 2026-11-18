"""macOS adapter. Mutations are only called by the administrator transaction."""
import copy
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import socket
import time

from guardlib import *

CLIENT_ID = 'io.github.clash-verge-rev.clash-verge-rev'
SERVICE_LABEL = CLIENT_ID + '.service'
SERVICE_PLIST = Path('/Library/LaunchDaemons/' + SERVICE_LABEL + '.plist')


def network_snapshot():
    services = run(['/usr/sbin/networksetup', '-listallnetworkservices']).stdout.splitlines()[1:]
    result = {}
    for name in services:
        if not name or name.startswith('*'):
            continue
        require(not name.startswith('-') and '\n' not in name, 'Invalid network service name')
        dnsraw = run(['/usr/sbin/networksetup', '-getdnsservers', name]).stdout.strip()
        dns = []
        for line in dnsraw.splitlines():
            try:
                ipaddress.ip_address(line.split('%')[0])
                dns.append(line)
            except ValueError:
                require("aren't any DNS Servers" in dnsraw, 'Unrecognized DNS response for ' + name)
        item = {'dns': dns}
        for kind, arg in [('http', '-getwebproxy'), ('https', '-getsecurewebproxy'),
                          ('socks', '-getsocksfirewallproxy'), ('pac', '-getautoproxyurl')]:
            raw = run(['/usr/sbin/networksetup', arg, name]).stdout
            item[kind] = dict(line.split(': ', 1) for line in raw.splitlines() if ': ' in line)
        result[name] = item
    require(result, 'No enabled network services found')
    return result


def restore_network(snapshot, log=print):
    steps = []
    for name, item in snapshot.items():
        steps.append(('DNS ' + name, lambda n=name, v=item['dns']: run(['/usr/sbin/networksetup', '-setdnsservers', n] + (v or ['Empty']))))
        for key, setter, state in [('http', '-setwebproxy', '-setwebproxystate'),
                                    ('https', '-setsecurewebproxy', '-setsecurewebproxystate'),
                                    ('socks', '-setsocksfirewallproxy', '-setsocksfirewallproxystate')]:
            p = item[key]
            if p.get('Server') and str(p.get('Port', '0')).isdigit() and int(p['Port']) > 0:
                args = ['/usr/sbin/networksetup', setter, name, p['Server'], p['Port']]
                steps.append((key + ' endpoint ' + name, lambda a=args: run(a)))
            args = ['/usr/sbin/networksetup', state, name, 'on' if p.get('Enabled') == 'Yes' else 'off']
            steps.append((key + ' state ' + name, lambda a=args: run(a)))
        if item['pac'].get('URL') and item['pac']['URL'] != '(null)':
            args = ['/usr/sbin/networksetup', '-setautoproxyurl', name, item['pac']['URL']]
            steps.append(('PAC URL ' + name, lambda a=args: run(a)))
        args = ['/usr/sbin/networksetup', '-setautoproxystate', name, 'on' if item['pac'].get('Enabled') == 'Yes' else 'off']
        steps.append(('PAC state ' + name, lambda a=args: run(a)))
    errors = restore_steps(steps, log)
    require(not errors, '; '.join(errors))


def set_network(settings, system_proxy=True):
    for name in settings['services']:
        run(['/usr/sbin/networksetup', '-setdnsservers', name, settings['tun_dns']])
        for kind in ['webproxy', 'securewebproxy', 'socksfirewallproxy']:
            run(['/usr/sbin/networksetup', '-set' + kind, name, '127.0.0.1', str(settings['mixed_port'])])
            run(['/usr/sbin/networksetup', '-set' + kind + 'state', name, 'on' if system_proxy else 'off'])
        run(['/usr/sbin/networksetup', '-setautoproxystate', name, 'off'])


def clear_owned_network(settings, baseline):
    """Only remove values owned by this deployment; preserve intervening VPN changes."""
    current = network_snapshot()
    for name in settings['services']:
        if name not in current:
            continue
        item = current[name]
        if item['dns'] == [settings['tun_dns']]:
            run(['/usr/sbin/networksetup', '-setdnsservers', name] + (baseline[name]['dns'] or ['Empty']))
        for key, kind in [('http', 'web'), ('https', 'secureweb'), ('socks', 'socksfirewall')]:
            p = item[key]
            if p.get('Server') in ['127.0.0.1', 'localhost'] and int(p.get('Port') or 0) in settings['ports']:
                run(['/usr/sbin/networksetup', '-set' + kind + 'proxystate', name, 'off'])
        # PAC was disabled by us, never enable another application's PAC here.


def find_socket(config_dir, uid, secret=''):
    candidates = [Path('/var/run/clash-verge-service/users') / str(uid) / 'verge-mihomo.sock']
    for filename in ['clash-verge.yaml', 'config.yaml']:
        p = Path(config_dir) / filename
        if p.is_file():
            cfg = yaml_read(p) or {}
            s = cfg.get('external-controller-unix')
            if isinstance(s, str) and s.startswith('/'):
                candidates.append(Path(s))
    for path in candidates:
        if not path.exists() or not stat.S_ISSOCK(path.stat().st_mode):
            continue
        settings = {'api_socket': str(path), 'api_secret': secret}
        try:
            api(settings, '/version')
            return str(path)
        except Exception:
            pass
    return str(candidates[0])


def gui_processes(s):
    return [p for p in processes() if p['uid'] == s['uid'] and p['path'] == s['gui_path']]


def stop_gui(s):
    run(['/bin/launchctl', 'bootout', 'gui/%s/%s' % (s['uid'], CLIENT_ID)], check=False)
    for row in gui_processes(s):
        os.kill(row['pid'], signal.SIGTERM)
    end = time.monotonic() + 12
    while gui_processes(s) and time.monotonic() < end:
        time.sleep(.3)
    for row in gui_processes(s):
        os.kill(row['pid'], signal.SIGKILL)
    require(not gui_processes(s), 'GUI did not stop; no config files will be replaced')


def user_run(s, args, timeout=20, check=True):
    prefix = []
    if os.geteuid() == 0:
        prefix = ['/usr/bin/sudo', '-H', '-u', s['user'], '/usr/bin/env', '-i',
                  'HOME=' + s['home'], 'PATH=' + SAFE_ENV['PATH'], 'LANG=en_US.UTF-8']
    else:
        require(os.geteuid() == s['uid'], 'Wrong user for acceptance test')
    return run(prefix + args, timeout=timeout, check=check,
               env=dict(SAFE_ENV, HOME=s['home']))


def open_gui(s):
    args = ['/usr/bin/open', '-a', s['app']]
    if os.geteuid() == 0:
        args = ['/bin/launchctl', 'asuser', str(s['uid']), '/usr/bin/sudo', '-H', '-u', s['user']] + args
    run(args)


def root_core(s):
    candidates = [p for p in processes() if p['uid'] == 0 and p['path'] in s['core_paths']]
    for p in candidates:
        out = run(['/usr/sbin/lsof', '-nP', '-a', '-p', str(p['pid']), '-U', '-Fn'], check=False).stdout
        if 'n' + s['api_socket'] in out.splitlines():
            secure_root(p['path'])
            return p
    raise GuardError('API socket is not owned by the verified root core')


def actual_tun(s):
    require(gui_processes(s), 'GUI not running')
    p = root_core(s)
    c = api(s, '/configs')
    require(c.get('mode') == 'rule' and c.get('ipv6') is False and c.get('mixed-port') == s['mixed_port'], 'Unexpected runtime mode/IPv6/listener')
    tun = c.get('tun') or {}
    require(tun.get('enable') is True and re.fullmatch(r'utun[0-9]{1,5}', tun.get('device', '')), 'TUN disabled or unknown')
    require(tun['device'] == s['device'], 'Unexpected TUN interface; re-prepare after conflict inspection')
    out = run(['/sbin/ifconfig', tun['device']]).stdout
    require('inet ' + s['tun_address'] + ' ' in out, 'TUN address not owned by this deployment')
    route = run(['/sbin/route', '-n', 'get', '1.1.1.1']).stdout
    require(re.search(r'interface:\s+' + re.escape(tun['device']) + r'\b', route), 'Public route does not use TUN')
    require(any(q == p for q in processes()), 'Core changed during verification')
    return tun['device']


def curl_probe(s, url, seconds=12, explicit_proxy=False):
    # -q must be the first curl option. No environment or .curlrc proxy can participate.
    args = ['/usr/bin/curl', '-q', '-4', '--silent', '--show-error', '--connect-timeout', '5',
            '--max-time', str(seconds), '--max-filesize', '131072', '--proto', '=http,https']
    if explicit_proxy:
        args += ['--proxy', 'http://127.0.0.1:' + str(s['mixed_port']), '--noproxy', '']
    else:
        args += ['--noproxy', '*']
    args += ['--write-out', '\n__GUARD__%{http_code} %{remote_ip} %{time_total}', url]
    p = user_run(s, args, timeout=seconds + 5, check=False)
    body, _, footer = p.stdout.rpartition('\n__GUARD__')
    parts = footer.split()
    result = {'url': url, 'uid': s['uid'], 'exit': p.returncode,
              'http': int(parts[0]) if parts and parts[0].isdigit() else 0,
              'remote_ip': parts[1] if len(parts) > 1 else '', 'explicit_proxy': explicit_proxy}
    # Bodies are used for IP/country only, never retained verbatim in reports.
    result['ip'] = ''
    result['country'] = ''
    try:
        value = json.loads(body)
        if isinstance(value, dict):
            rawip = value.get('ip') or value.get('origin') or value.get('query')
            if rawip:
                result['ip'] = str(ipaddress.ip_address(str(rawip).strip()))
            result['country'] = str(value.get('country') or value.get('countryCode') or '')
    except (ValueError, TypeError):
        try:
            result['ip'] = str(ipaddress.ip_address(body.strip()))
        except ValueError:
            # Arbitrary page text can contain unrelated addresses; never guess the caller's IP.
            pass
    result['reachable'] = p.returncode in (0, 63) and result['http'] > 0
    return result


def health(s, seconds=120, needs_tun=True):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            if needs_tun:
                actual_tun(s)
            with socket.create_connection(('127.0.0.1', s['mixed_port']), timeout=2):
                pass
            result = curl_probe(s, 'https://claude.ai', seconds=min(8, max(1, int(end-time.monotonic()))), explicit_proxy=not needs_tun)
            if result['reachable']:
                return result
        except Exception:
            pass
        time.sleep(1)
    raise GuardError('Ordinary-user claude.ai connectivity did not recover within %ss' % seconds)


def baseline_health(s, seconds=120):
    """First-import rollback must restore capabilities that existed before import."""
    baseline = s.get('original_health', {})
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            with socket.create_connection(('127.0.0.1', s['mixed_port']), timeout=2):
                pass
            if baseline.get('proxy_claude'):
                require(curl_probe(s, 'https://claude.ai', seconds=6, explicit_proxy=True)['reachable'], 'Original proxy transport unavailable')
            elif baseline.get('native'):
                require(baseline.get('native_url'), 'Recorded native test URL is missing')
                require(curl_probe(s, baseline['native_url'], seconds=6)['reachable'], 'Original native transport unavailable')
            return {'proxy_port': True, 'external_verified': bool(baseline.get('proxy_claude') or baseline.get('native')),
                    'basis': 'recorded pre-import capabilities; not new overseas acceptance'}
        except Exception:
            time.sleep(1)
    raise GuardError('Recorded original client/network baseline did not recover')


def launch_plist(s):
    return plistlib.dumps({'Label': CLIENT_ID, 'ProgramArguments': [s['gui_path']], 'RunAtLoad': True})


def install_login(s):
    p = Path(s['login_path'])
    require(not p.is_symlink(), 'Login plist is a symlink')
    p.parent.mkdir(parents=True, exist_ok=True)
    if os.geteuid() == 0:
        os.chown(p.parent, s['uid'], s['gid'])
    atomic(p, launch_plist(s), mode=0o644, owner=(s['uid'], s['gid']))
    run(['/bin/launchctl', 'enable', 'gui/%s/%s' % (s['uid'], CLIENT_ID)])
    run(['/bin/launchctl', 'bootstrap', 'gui/' + str(s['uid']), str(p)], check=False)


def copy_user(source, target, s):
    target = Path(target)
    missing = []
    parent = target.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for parent in reversed(missing):
        parent.mkdir(mode=0o700)
        os.chown(parent, s['uid'], s['gid'])
    atomic(target, Path(source).read_bytes(), owner=(s['uid'], s['gid']))


def restore_config(snapshot, s):
    target = Path(s['config_dir'])
    require(target.is_dir() and not target.is_symlink(), 'Unsafe config target')
    # Copy and validate BEFORE moving live data. Disk-full/partial-copy errors
    # must never strand a half-populated live directory.
    nonce = str(time.time_ns())
    staged = target.with_name(target.name + '.guard-restore-staging-' + nonce)
    failed = target.with_name(target.name + '.guard-failed-' + nonce)
    shutil.copytree(Path(snapshot) / 'config', staged)
    require(manifest(staged) == manifest(Path(snapshot) / 'config'), 'Staged recovery copy is incomplete')
    for p in [staged] + list(staged.rglob('*')):
        require(not p.is_symlink(), 'Unsafe restored config symlink')
        os.chown(p, s['uid'], s['gid'])
    os.rename(target, failed)
    try:
        os.rename(staged, target)
    except Exception:
        if not target.exists():
            os.rename(failed, target)
        raise
    login = Path(s['login_path'])
    saved = Path(snapshot) / 'login.plist'
    if saved.exists():
        atomic(login, saved.read_bytes(), mode=0o644, owner=(s['uid'], s['gid']))
    elif login.exists():
        login.unlink()


def snapshot_to(destination, s):
    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=False)
    require(not Path(s['config_dir']).is_symlink(), 'Symlinked config directory unsupported')
    before = manifest(s['config_dir'])
    shutil.copytree(s['config_dir'], dest / 'config')
    copied = manifest(dest / 'config')
    # Logs may change while running; critical configuration must remain stable.
    for relative, digest in before.items():
        if relative.endswith(('.yaml', '.yml', '.js', '.json')) and not relative.startswith(('logs/', 'cache/')):
            require(copied.get(relative) == digest and sha(Path(s['config_dir']) / relative) == digest,
                    'Configuration changed during backup; prepare again')
    if Path(s['login_path']).exists():
        shutil.copyfile(s['login_path'], dest / 'login.plist')
    dump(dest / 'network.json', network_snapshot())
    dump(dest / 'state.json', {'gui_running': bool(gui_processes(s)), 'service_present': SERVICE_PLIST.exists()})
    dump(dest / 'checksums.json', manifest(dest))
    atomic(dest / 'COMPLETE', 'complete\n')
