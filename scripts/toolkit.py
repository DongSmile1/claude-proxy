#!/usr/bin/env python3
"""Discovery, deterministic preparation and administrator entrypoint generation."""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import plistlib
import pwd
import re
import shlex
import shutil
import sys
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guardlib import *
from macos import CLIENT_ID, SERVICE_PLIST, find_socket, gui_processes, launch_plist, network_snapshot, snapshot_to, curl_probe

SCRIPTS = Path(__file__).resolve().parent
COMMANDS = ['/usr/bin/python3', '/usr/bin/ruby', '/usr/bin/curl', '/usr/bin/plutil', '/usr/bin/open',
            '/usr/bin/sudo', '/usr/bin/env', '/usr/bin/dig', '/usr/sbin/networksetup', '/usr/sbin/lsof',
            '/sbin/pfctl', '/sbin/ifconfig', '/sbin/route', '/usr/sbin/netstat', '/bin/launchctl', '/bin/ps', '/bin/sh']


def discover(home=None, app_roots=None, measure=False):
    home = Path(home or Path.home())
    roots = app_roots or [Path('/Applications'), home / 'Applications']
    known = [('Clash Verge.app', 'clash-verge-rev'), ('Mihomo Party.app', 'mihomo-party'),
             ('Clash Party.app', 'mihomo-party'), ('Surge.app', 'surge'), ('sing-box.app', 'sing-box')]
    clients = []
    for root in roots:
        for name, kind in known:
            app = Path(root) / name
            if not app.exists():
                continue
            info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
            version = info.get('CFBundleShortVersionString', '')
            supported = kind == 'clash-verge-rev' and platform.system() == 'Darwin' and version == '2.5.10'
            clients.append({'client': kind, 'app': str(app), 'version': version, 'supported': supported,
                            'executable': str(app / 'Contents/MacOS' / info.get('CFBundleExecutable', ''))})
    report = {'schema': SCHEMA, 'os': platform.system(), 'arch': platform.machine(), 'clients': clients,
              'uid': os.getuid(), 'home': str(home), 'support': 'macOS + Clash Verge Rev 2.5.10; other versions need adapter verification',
              'conflicts': [], 'nodes': []}
    if platform.system() != 'Darwin':
        report['blockers'] = ['No native firewall/installation adapter for this OS']
        return report
    report['commands'] = {p: os.access(p, os.X_OK) for p in COMMANDS}
    rows = processes()
    report['processes'] = [p for p in rows if re.search(r'clash|mihomo|surge|sing-box|v2ray|tailscale|proxyman', p['path'], re.I)]
    for p in report['processes']:
        if re.search(r'surge|sing-box|v2ray|tailscale|proxyman|mihomo.party', p['path'], re.I):
            report['conflicts'].append('process:' + p['path'])
    report['interfaces'] = run(['/sbin/ifconfig', '-l']).stdout.split()
    other_tunnels = [n for n in report['interfaces'] if n.startswith('utun')]
    if other_tunnels:
        report['conflicts'].append('existing-tunnel-interfaces:' + ','.join(other_tunnels))
    routes = run(['/usr/sbin/netstat', '-rn', '-f', 'inet']).stdout
    report['route_networks'] = route_networks(routes)
    report['network'] = network_snapshot()
    report['dns_summary'] = run(['/usr/sbin/scutil', '--dns']).stdout
    report['proxy_summary'] = run(['/usr/sbin/scutil', '--proxy']).stdout
    if '100.100.100.100' in report['dns_summary']:
        report['conflicts'].append('tailscale-dns')
    report['existing_guard'] = GUARD.exists() or LAUNCH.exists()
    if report['existing_guard']:
        report['conflicts'].append('existing-clash-guard')
    config_dir = home / 'Library/Application Support' / CLIENT_ID
    report['config_dir'] = str(config_dir)
    report['service_present'] = SERVICE_PLIST.exists()
    if config_dir.is_dir():
        cfg = yaml_read(config_dir / 'config.yaml') or {}
        secret = cfg.get('secret') or ''
        settings = {'api_socket': find_socket(config_dir, os.getuid(), secret), 'api_secret': secret}
        report['api_socket'] = settings['api_socket']
        try:
            c = api(settings, '/configs')
            report['runtime'] = {k: c.get(k) for k in ['mode', 'ipv6', 'mixed-port', 'port', 'socks-port', 'tun']}
            data = api(settings, '/proxies').get('proxies', {})
            for name, node in data.items():
                if node.get('all') is not None or str(node.get('type', '')).lower() not in ['shadowsocks', 'shadowsocksr', 'vmess', 'vless', 'trojan', 'socks5', 'http', 'hysteria2', 'tuic', 'anytls']:
                    continue
                if re.search(r'剩余|到期|官网|流量|expire|traffic|website', name, re.I):
                    continue
                item = {'name': name, 'type': node.get('type'), 'delay_ms': None, 'region': 'unverified'}
                if measure:
                    try:
                        value = api(settings, '/proxies/' + urllib.parse.quote(name, safe='') + '/delay?' +
                                    urllib.parse.urlencode({'url': 'https://www.gstatic.com/generate_204', 'timeout': 6000}), timeout=8)
                        item['delay_ms'] = value.get('delay')
                    except Exception:
                        item['error'] = 'delay_failed'
                report['nodes'].append(item)
            report['nodes'].sort(key=lambda n: n['delay_ms'] if type(n['delay_ms']) is int else 999999)
        except Exception as e:
            report['api_error'] = str(e)
    return report


def empty_extension(path):
    if not path.exists():
        return True
    if path.suffix in ['.yaml', '.yml']:
        value = yaml_read(path)
        return value is None or value == {} or value == [] or value == {'prepend': [], 'append': [], 'delete': []}
    text = re.sub(r'/\*.*?\*/|//[^\n]*', '', path.read_text(), flags=re.S).strip()
    return not text or bool(re.fullmatch(r'function\s+main\s*\(\s*config\s*(?:,\s*\w+\s*)?\)\s*\{\s*return\s+config\s*;?\s*\}', text))


def profile_details(config_dir, replace_global=False, allow_empty_current=False):
    info = yaml_read(config_dir / 'profiles.yaml')
    require(isinstance(info, dict) and isinstance(info.get('items'), list), 'Unknown profiles.yaml schema')
    items = {i['uid']: i for i in info['items']}
    require((allow_empty_current or info.get('current') in items) and 'Script' in items and 'Merge' in items, 'Current profile/global extensions not initialized')
    for item in items.values():
        filename = item.get('file', '')
        require(isinstance(filename, str) and filename == Path(filename).name and filename, 'Unsafe profile path')
    current = items.get(info.get('current'))
    require(allow_empty_current or current.get('type') in ['local', 'remote'], 'Select an actual subscription/local profile first')
    # Any later extension may replace the global result, including on another profile.
    for item in items.values():
        if item['uid'] not in ['Merge', 'Script'] and item.get('type') in ['merge', 'script', 'rules', 'proxies', 'groups']:
            require(empty_extension(config_dir / 'profiles' / item['file']), 'A subscription extension has behavior; review/merge it before automatic deployment: ' + item['file'])
    for uid in ['Merge', 'Script']:
        require(replace_global or empty_extension(config_dir / 'profiles' / items[uid]['file']),
                'Existing global extension requires explicit replacement approval: ' + uid)
    return info, current, items


def check_options(o):
    require(o.get('approved') is True, 'Record the user-approved plan in options.json before prepare')
    for key in ['native_on_both_off', 'native_on_gui_exit', 'udp_verified', 'replace_global_extension']:
        require(type(o.get(key)) is bool, 'Explicit boolean choice required: ' + key)
    require(o.get('exit_mode') in ['A', 'B'], 'Choose exit mode A or B')
    country = o.get('expected_exit_country', '')
    require(re.fullmatch(r'[A-Z]{2}', country) and country not in ['CN', 'HK', 'MO'], 'Verify an eligible overseas exit country first')
    require(o.get('region_verified') is True, 'Verify selected exit region, not just the node name')
    ipaddress.ip_address(o['expected_exit_ip'])
    require(ipaddress.ip_address(o['expected_exit_ip']).is_global, 'Expected exit must be a public address')
    require(isinstance(o.get('acknowledged_conflicts', []), list), 'Invalid conflict acknowledgements')
    allowed = {'approved', 'nodes', 'exit_mode', 'expected_exit_country', 'expected_exit_ip', 'region_verified',
               'native_on_both_off', 'native_on_gui_exit', 'udp_verified', 'replace_global_extension',
               'acknowledged_conflicts', 'overseas_domains', 'direct_domains', 'residential', 'services',
               'app', 'kill_existing_states', 'allow_default_pf_reload', 'accepted_exceptions', 'domestic_tests'}
    require(not set(o) - allowed, 'Unknown options: ' + ', '.join(sorted(set(o) - allowed)))
    require(o.get('kill_existing_states') is True, 'Existing physical-interface states require an explicit approved one-time cleanup')
    require(type(o.get('allow_default_pf_reload')) is bool, 'Choose whether unchanged Apple PF defaults may be loaded into an empty ruleset')
    exceptions = o.get('accepted_exceptions', {})
    require(isinstance(exceptions, dict) and not set(exceptions) - {'statsig.anthropic.com', 'external_dns_leak'}, 'Only unavailable external checks can have named evidence exceptions')
    require(all(isinstance(v, str) and len(v.strip()) >= 10 for v in exceptions.values()), 'Every accepted exception needs a concrete explanation/evidence')
    domestic_tests(o)


def download_rules(stage, config_dir, proxy_port):
    details = {}
    transport = ['--proxy', 'http://127.0.0.1:' + str(proxy_port), '--noproxy', '']
    for name, url in PROVIDERS.items():
        p = stage / 'ruleset' / (name + '.yaml')
        p.parent.mkdir(exist_ok=True)
        run(['/usr/bin/curl', '-q', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
             '--proto-redir', '=https', '--max-time', '45', '--max-filesize', '16777216', '--output', str(p)] + transport + [url], timeout=50)
        value = yaml_read(p)
        minimum = 10 if name == 'guard-wechat' else 100
        require(isinstance(value, dict) and isinstance(value.get('payload'), list) and len(value['payload']) > minimum,
                'Invalid/empty remote rule resource: ' + name)
        details[name] = {'sha256': sha(p), 'count': len(value['payload']), 'url': url, 'downloaded_at': time.time()}
    geo = config_dir / 'geosite.dat'
    if not geo.is_file():
        geo = stage / 'geosite.dat'
        run(['/usr/bin/curl', '-q', '--fail', '--silent', '--show-error', '--location', '--proto', '=https', '--proto-redir', '=https',
             '--max-time', '90', '--max-filesize', '67108864', '--output', str(geo)] + transport +
             ['https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat'], timeout=95)
    else:
        shutil.copyfile(geo, stage / 'geosite.dat')
    require((stage / 'geosite.dat').stat().st_size > 10000, 'GeoSite cache missing/invalid')
    details['geosite'] = {'sha256': sha(stage / 'geosite.dat')}
    return details


def shell_entry(action):
    return '''#!/bin/sh
set -u
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
unset PYTHONPATH PYTHONHOME ENV BASH_ENV CDPATH
umask 077
[ "$(/usr/bin/id -u)" = 0 ] || { echo '请在终端用 sudo sh 运行此脚本。'; exit 77; }
BASE=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P) || exit 2
exec /usr/bin/python3 -I -B "$BASE/engine/admin.py" %s "$BASE"
''' % shlex.quote(action)


def emergency(s, backup):
    off = 'sudo sh "/Library/Application Support/clash-guard/off.sh"'
    lines = ['断网急救（请在改动前用手机保存）', '', '1. 打开客户端，等一分钟：',
             '/usr/bin/open -a ' + shlex.quote(s['app']), '', '2. 仍不通，打开“终端”，按顺序执行：', off,
             'sudo sh ' + shlex.quote(str(backup / 'restore.sh')), '', '3. 上面文件不存在时执行：',
             'sudo launchctl bootout system/local.clash-guard', 'sudo pfctl -a com.apple/clash-guard -F all',
             '', '4. 关闭本次涉及网络服务的系统代理，并恢复备份时 DNS：']
    baseline = read_json(backup / 'original/network.json')
    for service in s['services']:
        for flag in ['-setwebproxystate', '-setsecurewebproxystate', '-setsocksfirewallproxystate', '-setautoproxystate']:
            lines.append('sudo /usr/sbin/networksetup ' + flag + ' ' + shlex.quote(service) + ' off')
        lines.append('sudo /usr/sbin/networksetup -setdnsservers ' + shlex.quote(service) + ' ' +
                     ' '.join(shlex.quote(v) for v in (baseline[service]['dns'] or ['Empty'])))
    lines += ['', '5. 网络恢复后回到原对话说：“网断过，先查现状再继续”。不要从头重复安装。',
              '', '解除防护会允许后续请求使用原网络；并不保证只放行国内网站。',
              '外部网络或节点本身故障时，恢复脚本不能保证互联网一定可达。']
    return '\n'.join(lines) + '\n'


def imported_profile(profiles, node):
    """A new local profile; never replace a subscription or its credentials."""
    validate_node(node)
    uid = 'guard-node-' + os.urandom(8).hex()
    item = {'uid': uid, 'type': 'local', 'name': node['name'], 'file': uid + '.yaml',
            'desc': 'Managed VPS node; credentials remain local', 'updated': int(time.time())}
    result = copy.deepcopy(profiles)
    result['items'].append(item); result['current'] = uid
    return result, item, {'proxies': [node], 'rules': ['MATCH,' + node['name']]}


def prepare(options_file, output=None, node_file=None, node_evidence=None):
    require(os.geteuid() != 0, 'prepare must run as the desktop user')
    require(platform.system() == 'Darwin', 'No deployment adapter for this OS')
    options = read_json(options_file)
    check_options(options)
    report = discover()
    choices = [c for c in report['clients'] if c['supported'] and (not options.get('app') or c['app'] == options['app'])]
    require(len(choices) == 1, 'Exactly one supported client must be selected; inspect discovery report')
    require(not report['existing_guard'], 'An existing guard is present: use repair/migration review, never overwrite it with a fresh installer')
    require(all(report['commands'].values()), 'Missing system commands: ' + str([k for k, v in report['commands'].items() if not v]))
    run([PYTHON, '-I', '-c', 'import sys; assert sys.version_info >= (3, 9)'])
    missing = set(report['conflicts']) - set(options.get('acknowledged_conflicts', []))
    require(not missing, 'Unreviewed competing proxy/VPN: ' + ', '.join(sorted(missing)))
    require('tailscale-dns' not in report['conflicts'], 'Resolve active Tailscale DNS takeover before prepare')
    client = choices[0]
    config_dir = Path(report['config_dir'])
    require(config_dir.is_dir(), 'Launch the client and import/select a subscription first')
    planning_files = [config_dir / n for n in ['config.yaml', 'verge.yaml', 'profiles.yaml']]
    planning_files += [p for p in (config_dir / 'profiles').rglob('*') if p.is_file()]
    planning_hashes = {str(p.relative_to(config_dir)): sha(p) for p in planning_files}
    require(bool(node_file) == bool(node_evidence), 'A new node requires its deployment evidence')
    profiles, current, items = profile_details(config_dir, options['replace_global_extension'], bool(node_file))
    imported = None
    core_for_probe = Path(client['app']) / 'Contents/MacOS/verge-mihomo'
    if node_file:
        from vps import probe
        node_file = Path(node_file).expanduser().absolute()
        proof = read_json(node_evidence)
        require(proof.get('passed') is True and proof.get('node_sha256') == sha(node_file), 'Node evidence/credentials mismatch')
        require((node_file.parent / 'COMMITTED').is_file(), 'Server deployment is not committed')
        require(options['exit_mode'] == 'A' and options['nodes'] == [read_json(node_file)['name']], 'Bare VPS auto-import currently supports mode A only')
        fresh = probe(core_for_probe, node_file)
        require(fresh['ip'] == options['expected_exit_ip'] and fresh['country'] == options['expected_exit_country'], 'Fresh node probe differs from approved exit')
        profiles, current, imported = imported_profile(profiles, read_json(node_file))
        require(not (config_dir / 'profiles' / current['file']).exists(), 'Import filename collision')
        original = imported
    else:
        original = yaml_read(config_dir / 'profiles' / current['file'])
    prefs = yaml_read(config_dir / 'verge.yaml')
    appcfg = yaml_read(config_dir / 'config.yaml')
    require(isinstance(prefs, dict) and isinstance(appcfg, dict), 'Unrecognized client settings schema')
    require(prefs.get('clash_core') in [None, 'verge-mihomo'], 'Select the supported stable core before automatic deployment')
    require(all(k in prefs for k in ['enable_tun_mode', 'enable_system_proxy', 'enable_auto_launch']), 'Unsupported Verge preference schema')
    require(prefs.get('enable_tun_mode') is not True, 'Fresh deployment requires a known native baseline; an existing TUN setup needs the repair/migration workflow')
    port = prefs.get('verge_mixed_port') or appcfg.get('mixed-port')
    require(type(port) is int and 1 <= port <= 65535, 'Could not discover the configured mixed proxy port')
    require(not gui_processes({'uid': os.getuid(), 'gui_path': client['executable']}) or report.get('runtime'), 'Running client API is unavailable')
    if report.get('runtime'):
        require(report['runtime'].get('mixed-port') == port, 'Runtime and saved ports differ; resolve the port collision first')
        for n in ([] if imported else options['nodes']):
            delay = api({'api_socket': report['api_socket'], 'api_secret': appcfg.get('secret', '')},
                        '/proxies/' + urllib.parse.quote(n, safe='') + '/delay?' +
                        urllib.parse.urlencode({'url': 'https://www.gstatic.com/generate_204', 'timeout': 7000}), timeout=9)
            require(type(delay.get('delay')) is int and delay['delay'] > 0, 'Selected node did not pass delay check')
    else:
        raise GuardError('Start the client and verify the selected node before prepare; no untested exit can be applied')
    services = options.get('services') or list(report['network'])
    require(isinstance(services, list) and services and set(services) <= set(report['network']), 'Unknown network service')
    for name in services:
        require(not any(ipaddress.ip_address(x.split('%')[0]) in ipaddress.ip_network('198.18.0.0/15')
                        for x in report['network'][name]['dns'] if ':' not in x),
                'Saved DNS still points at a previous fake-IP pool; establish a native DNS baseline first')
        for k in ['http', 'https', 'socks']:
            require(report['network'][name][k].get('Authenticated Proxy Enabled', '0') in ['0', 'No'],
                    'Authenticated system proxy cannot be losslessly restored; exclude/review this service: ' + name)
    pool = pick_pool(report['route_networks'])
    device = next('utun' + str(i) for i in range(8, 256) if 'utun' + str(i) not in report['interfaces'])
    target = build_config(original, options, pool, device)
    identity = pwd.getpwuid(os.getuid())
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(3).hex()
    backup = Path(output).expanduser().absolute() if output else Path.home() / 'clash-guard-backup' / stamp
    require(not backup.exists(), 'Output exists; do not reuse a transaction directory')
    backup.mkdir(parents=True, mode=0o700)
    os.chmod(backup, 0o700)
    app = Path(client['app'])
    installer = app / 'Contents/Resources/resources/clash-verge-service-install'
    uninstaller = app / 'Contents/Resources/resources/clash-verge-service-uninstall'
    core = app / 'Contents/MacOS/verge-mihomo'
    binaries = [core]
    if not report['service_present']:
        binaries += [installer, uninstaller]
    require(all(p.is_file() and os.access(p, os.X_OK) for p in binaries), 'Missing official service installer/core')
    s = {'schema': SCHEMA, 'id': stamp, 'uid': identity.pw_uid, 'gid': identity.pw_gid, 'user': identity.pw_name,
         'home': identity.pw_dir, 'app': str(app), 'gui_path': client['executable'], 'client_version': client['version'],
         'config_dir': str(config_dir), 'login_path': str(Path.home() / 'Library/LaunchAgents' / (CLIENT_ID + '.plist')),
         'api_socket': report['api_socket'] if report['service_present'] else '/var/run/clash-verge-service/users/' + str(identity.pw_uid) + '/verge-mihomo.sock', 'api_secret': appcfg.get('secret', ''),
         'core_paths': ['/Library/Application Support/clash-verge-service/cores/verge-mihomo'],
         'core': str(core), 'installer': str(installer), 'uninstaller': str(uninstaller),
         'binary_hashes': {str(p): sha(p) for p in binaries}, 'needs_service': not report['service_present'],
         'mixed_port': port, 'ports': sorted(set([port] + [int(appcfg[k]) for k in ['port', 'socks-port', 'redir-port'] if appcfg.get(k)])),
         'device': device, 'pool': pool, 'tun_address': str(ipaddress.ip_network(pool).network_address + 1),
         'tun_dns': str(ipaddress.ip_network(pool).network_address + 2), 'services': services,
         'options': options, 'backup': str(backup), 'subscription': 'profiles/' + current['file'],
         'script_file': 'profiles/' + items['Script']['file'], 'merge_file': 'profiles/' + items['Merge']['file'],
         'pf_hashes': {p: sha(p) for p in ['/etc/pf.conf', '/etc/pf.anchors/com.apple']}}
    # Full backup is complete before preparing anything that could be applied.
    snapshot_to(backup / 'original', s)
    saved_config = backup / 'original/config'
    critical = [saved_config / 'config.yaml', saved_config / 'verge.yaml', saved_config / 'profiles.yaml']
    critical += [p for p in (saved_config / 'profiles').rglob('*') if p.is_file()]
    expected_live = {str(p.relative_to(saved_config)): sha(p) for p in critical}
    require(expected_live == planning_hashes, 'Configuration changed while planning/backing up; prepare a new batch')
    stage = backup / 'stage'
    stage.mkdir(mode=0o700)
    engine = backup / 'engine'
    engine.mkdir(mode=0o700)
    for name in ['guardlib.py', 'macos.py', 'admin.py', 'accept.py']:
        shutil.copyfile(SCRIPTS / name, engine / name)
    script = extension(target, options)
    atomic(stage / 'Script.js', script)
    dump(stage / 'Merge.yaml', {})
    if imported:
        dump(stage / 'node-profile.yaml', imported)
        dump(stage / 'profiles.yaml', profiles)
        s['import_profile'] = True
        s['subscription_sha256'] = sha(stage / 'node-profile.yaml')
        native_url = domestic_tests(options)['urls'][0]
        s['original_health'] = {'native': False, 'native_url': native_url, 'proxy_claude': False}
        for key, url, explicit in [('native', native_url, False), ('proxy_claude', 'https://claude.ai', True)]:
            try:
                s['original_health'][key] = curl_probe(s, url, seconds=8, explicit_proxy=explicit)['reachable']
            except Exception:
                pass
    newprefs = copy.deepcopy(prefs)
    newprefs.update({'enable_tun_mode': True, 'enable_auto_launch': True, 'enable_system_proxy': True,
                     'enable_proxy_guard': False, 'enable_dns_settings': False, 'proxy_auto_config': False})
    newprefs['profile_dns_settings'] = {k: dict(v or {}, enabled=False) for k, v in (newprefs.get('profile_dns_settings') or {}).items()}
    newcfg = copy.deepcopy(appcfg)
    newcfg.update({'mode': 'rule', 'ipv6': False, 'allow-lan': False, 'log-level': 'info', 'tun': target['tun']})
    dump(stage / 'verge.yaml', newprefs)
    dump(stage / 'config.yaml', newcfg)
    target.update({k: newcfg[k] for k in ['mixed-port', 'external-controller', 'external-controller-unix', 'secret'] if k in newcfg})
    dump(stage / 'candidate.json', target)
    atomic(stage / 'login.plist', launch_plist(s))
    if imported:
        # Fresh clients have no working overseas node yet. Fetch through the isolated,
        # already verified node, without changing the active GUI or system network.
        from vps import isolated_proxy
        with isolated_proxy(core, imported['proxies'][0]) as fetch_port:
            resources = download_rules(stage, config_dir, fetch_port)
    else:
        resources = download_rules(stage, config_dir, port)
    dump(stage / 'resource-evidence.json', resources)
    for kind, tun in [('restricted', ''), ('guarding', device)]:
        pf = stage / (kind + '.pf')
        atomic(pf, render_pf(tun, s['ports']))
        run(['/sbin/pfctl', '-n', '-f', str(pf)])
    run(['/usr/bin/plutil', '-lint', str(stage / 'login.plist')])
    # Native parser reads only a staged home and cannot mutate the active client.
    parsed = run([str(core), '-t', '-d', str(stage), '-f', str(stage / 'candidate.json')], timeout=60)
    atomic(stage / 'core-parse.log', parsed.stdout + parsed.stderr)
    dump(backup / 'settings.json', s)
    for action, filename in [('apply', 'apply.sh'), ('guard', 'install-guard.sh'), ('drill', 'drill.sh'), ('restore', 'restore.sh')]:
        atomic(backup / filename, shell_entry(action), mode=0o700)
        run(['/bin/sh', '-n', str(backup / filename)])
    for relative, digest in expected_live.items():
        require(sha(config_dir / relative) == digest, 'Live configuration changed during preparation; do not apply this batch: ' + relative)
    dump(backup / 'expected-live.json', expected_live)
    dump(backup / 'payload-sha256.json', manifest(backup))
    text = emergency(s, backup)
    atomic(backup / '断网急救.txt', text)
    desktop = Path.home() / 'Desktop/断网急救.txt'
    if desktop.exists():
        shutil.copyfile(desktop, backup / 'previous-emergency.txt')
    atomic(desktop, text)
    atomic(backup / 'PREPARED', 'complete\n')
    return {'backup': str(backup), 'apply': 'sudo sh ' + shlex.quote(str(backup / 'apply.sh')),
            'guard_after_acceptance': 'sudo sh ' + shlex.quote(str(backup / 'install-guard.sh')),
            'drills': 'sudo sh ' + shlex.quote(str(backup / 'drill.sh')), 'restore': 'sudo sh ' + shlex.quote(str(backup / 'restore.sh')),
            'emergency': str(desktop), 'changed_live_network': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    d = sub.add_parser('discover'); d.add_argument('--output', required=True); d.add_argument('--measure', action='store_true')
    q = sub.add_parser('prepare'); q.add_argument('--options', required=True); q.add_argument('--output')
    q.add_argument('--node-file'); q.add_argument('--node-evidence')
    sub.add_parser('options-template')
    r = sub.add_parser('report'); r.add_argument('--backup', required=True)
    a = p.parse_args()
    if a.command == 'discover':
        require(not Path(a.output).exists(), 'Report exists; choose a new output path')
        report = discover(measure=a.measure)
        dump(a.output, report)
        print(json.dumps({'report': str(Path(a.output).absolute()), 'clients': report['clients'], 'conflicts': report['conflicts'], 'nodes': report['nodes']}, ensure_ascii=False, indent=2))
    elif a.command == 'prepare':
        print(json.dumps(prepare(a.options, a.output, a.node_file, a.node_evidence), ensure_ascii=False, indent=2))
    elif a.command == 'report':
        directory = Path(a.backup).expanduser().absolute()
        items = {str(i): {'status': 'not_tested'} for i in range(1, 12)}
        for name in ['network.report.json', 'guard.report.json', 'drill.report.json']:
            path = directory / 'results' / name
            if path.is_file():
                items.update(read_json(path).get('items', {}))
        phases = {p.name: read_json(p) for p in (directory / 'results').glob('done-*')}
        print(json.dumps({'items': items, 'phases': phases, 'restore': 'sudo sh ' + shlex.quote(str(directory / 'restore.sh')),
                          'off': 'sudo sh "/Library/Application Support/clash-guard/off.sh"'}, ensure_ascii=False, indent=2))
    else:
        print(json.dumps({'approved': False, 'exit_mode': 'A', 'nodes': [], 'expected_exit_ip': '', 'expected_exit_country': '',
            'region_verified': False, 'udp_verified': False, 'native_on_both_off': False, 'native_on_gui_exit': False,
            'replace_global_extension': False, 'kill_existing_states': False, 'allow_default_pf_reload': False,
            'acknowledged_conflicts': [], 'accepted_exceptions': {}, 'overseas_domains': [], 'direct_domains': [],
            'domestic_tests': {'urls': [], 'ip_url': '', 'expected_ip': '', 'region_verified': False}}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (GuardError, ValueError, OSError, subprocess.SubprocessError) as e:
        print('ERROR: ' + str(e), file=sys.stderr)
        sys.exit(1)
