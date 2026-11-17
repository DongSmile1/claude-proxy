"""Shared, dependency-free building blocks. No network mutations on import."""
import copy
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time
import urllib.parse

SCHEMA = 1
GROUP = '海外出口'
GUARD = Path('/Library/Application Support/clash-guard')
LABEL = 'local.clash-guard'
ANCHOR = 'com.apple/clash-guard'
LAUNCH = Path('/Library/LaunchDaemons/local.clash-guard.plist')
PYTHON = '/usr/bin/python3'
CLAUDE = ['claude.ai', 'claude.com', 'anthropic.com', 'claudeusercontent.com', 'claudemcpclient.com']
LAN4 = ['10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16']
RESERVED = ['0.0.0.0/8', '192.0.0.0/24', '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4']
LAN6 = ['::1/128', 'fc00::/7', 'fe80::/10']
PROVIDERS = {n: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/' + f
             for n, f in [('guard-direct', 'direct.txt'), ('guard-cncidr', 'cncidr.txt')]}
PROVIDERS['guard-wechat'] = 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Wechat.yaml'
PROVIDER_BEHAVIOR = {'guard-direct': 'domain', 'guard-cncidr': 'ipcidr', 'guard-wechat': 'classical'}
SAFE_ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'en_US.UTF-8', 'LC_ALL': 'en_US.UTF-8'}


class GuardError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise GuardError(message)


def domestic_tests(options):
    """Require user-approved endpoints; never ship a domestic domain or invent a pass."""
    tests = options.get('domestic_tests')
    require(isinstance(tests, dict), 'Provide domestic_tests before preparing deployment')
    require(set(tests) == {'urls', 'ip_url', 'expected_ip', 'region_verified'}, 'Invalid domestic_tests fields')
    urls = tests['urls']
    require(isinstance(urls, list) and 2 <= len(urls) <= 4, 'Provide two to four ordinary domestic test URLs')
    hosts = []
    for url in urls + [tests['ip_url']]:
        require(isinstance(url, str) and len(url) <= 2048, 'Invalid domestic test URL')
        try:
            parts = urllib.parse.urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise GuardError('Invalid domestic test URL') from exc
        require(parts.scheme in ['http', 'https'] and parts.hostname and not parts.query and not parts.fragment
                and parts.username is None and parts.password is None and (port is None or 0 < port < 65536)
                and not any(ord(c) < 33 for c in url),
                'Use HTTP(S) URLs without credentials, query, fragment or whitespace')
        host = parts.hostname
        require(re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}', host)
                and not host.endswith(('.local', '.lan', '.localhost', '.invalid')),
                'Domestic acceptance needs ordinary public domain URLs, not raw IP or local hosts')
        hosts.append(host)
    require(len(set(hosts[:-1])) == len(urls), 'Ordinary domestic test hosts must be distinct')
    try:
        address = ipaddress.ip_address(tests['expected_ip'])
    except (ValueError, TypeError) as exc:
        raise GuardError('Record the verified native public IPv4 in domestic_tests.expected_ip') from exc
    require(address.version == 4 and address.is_global and str(address) != options.get('expected_exit_ip'),
            'Native exit must be a public IPv4 different from the overseas exit')
    require(tests['region_verified'] is True, 'Verify the native exit region before domestic acceptance')
    return tests


def run(argv, timeout=20, check=True, data=None, env=None):
    p = subprocess.run([str(x) for x in argv], input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, text=True, timeout=timeout, env=env or SAFE_ENV)
    if check and p.returncode:
        # Do not echo argv or arbitrary stderr: either can contain credentials.
        raise GuardError('%s failed (exit %s): %s' % (Path(str(argv[0])).name, p.returncode, p.stderr[-500:]))
    return p


def atomic(path, data, mode=0o600, owner=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.is_symlink(), 'Refusing symlink destination: ' + str(path))
    fd, temp = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        if owner is not None:
            os.fchown(fd, *owner)
        with os.fdopen(fd, 'wb') as f:
            f.write(data.encode() if isinstance(data, str) else data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def dump(path, value, **kwargs):
    atomic(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n', **kwargs)


def read_json(path):
    return json.loads(Path(path).read_text())


def verify_subscription_files(settings, bundle):
    target = Path(settings['config_dir'])
    before = read_json(Path(bundle) / 'expected-live.json')
    selected = settings['subscription']
    expected = settings['subscription_sha256'] if settings.get('import_profile') else before[selected]
    require(sha(target / selected) == expected, 'Selected node profile changed')
    if settings.get('import_profile'):
        for relative, digest in before.items():
            if relative.startswith('profiles/') and relative not in [settings['script_file'], settings['merge_file']]:
                require(sha(target / relative) == digest, 'An original subscription/extension changed: ' + relative)


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def manifest(root):
    root = Path(root)
    result = {}
    for p in sorted(root.rglob('*')):
        require(not p.is_symlink(), 'Symlinks in backup/config are not supported: ' + str(p))
        require(p.is_dir() or p.is_file(), 'Non-regular file in config: ' + str(p))
        if p.is_file():
            result[str(p.relative_to(root))] = sha(p)
    return result


def secure_root(path):
    """Check every existing component, including the executable itself."""
    p = Path(path).absolute()
    for part in [p] + list(p.parents):
        s = part.lstat()
        require(not stat.S_ISLNK(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'Privileged path is not root-owned/immutable to other users: ' + str(part))


def yaml_read(path):
    # macOS ships Ruby/Psych; safe_load forbids tags and aliases. JSON is YAML.
    text = Path(path).read_text()
    try:
        return json.loads(text)
    except ValueError:
        code = 'v=YAML.safe_load(STDIN.read,[],[],false); print JSON.generate(v)'
        return json.loads(run(['/usr/bin/ruby', '-ryaml', '-rjson', '-e', code], data=text).stdout)


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=4):
        super().__init__('localhost', timeout=timeout)
        self.unix_path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_path)


def api(settings, path, method='GET', payload=None, timeout=5):
    c = UnixHTTP(settings['api_socket'], timeout)
    try:
        headers = {'Content-Type': 'application/json'}
        if settings.get('api_secret'):
            headers['Authorization'] = 'Bearer ' + settings['api_secret']
        c.request(method, path, None if payload is None else json.dumps(payload), headers)
        r = c.getresponse()
        raw = r.read(16 * 1024 * 1024)
        require(200 <= r.status < 300, 'Core API HTTP %s for %s' % (r.status, path.split('?')[0]))
        return json.loads(raw) if raw else {}
    finally:
        c.close()


def processes():
    rows = run(['/bin/ps', '-axww', '-o', 'pid=,uid=,comm=']).stdout.splitlines()
    return [dict(pid=int(p[0]), uid=int(p[1]), path=p[2]) for row in rows
            for p in [row.strip().split(None, 2)] if len(p) == 3 and p[0].isdigit() and p[1].isdigit()]


def pick_pool(route_networks):
    nets = [ipaddress.ip_network(n, strict=False) for n in route_networks]
    for value in ['198.18.0.0/16', '198.19.0.0/16']:
        candidate = ipaddress.ip_network(value)
        if not any(n.version == 4 and n.prefixlen > 1 and candidate.overlaps(n) for n in nets):
            return value
    raise GuardError('Both benchmark address pools overlap existing routes; no safe automatic TUN pool.')


def route_networks(raw):
    nets = []
    for line in raw.splitlines():
        fields = line.split()
        if not fields or not re.match(r'^\d', fields[0]):
            continue
        token = fields[0]
        try:
            addr, _, prefix = token.partition('/')
            octets = addr.split('.')
            if len(octets) < 4:
                prefix = prefix or str(len(octets) * 8)
                addr += '.0' * (4 - len(octets))
            nets.append(str(ipaddress.ip_network(addr + '/' + (prefix or '32'), strict=False)))
        except ValueError:
            continue
    return nets


def domains(values):
    require(isinstance(values, list), 'Domains must be a list')
    out = []
    for s in values:
        require(isinstance(s, str) and len(s) <= 253 and
                re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', s) and '.' in s,
                'Invalid domain suffix')
        if s not in out:
            out.append(s)
    return out


def validate_node(n):
    require(isinstance(n, dict) and n.get('type') in
            ['ss', 'ssr', 'vmess', 'vless', 'trojan', 'socks5', 'http', 'hysteria2', 'tuic', 'anytls'],
            'Unsupported node protocol; an actual node is required')
    require(isinstance(n.get('name'), str) and n['name'] not in ['DIRECT', 'REJECT', GROUP, '跳板'] and
            not re.search(r'[\r\n,]', n['name']), 'Invalid/reserved node name')
    require(isinstance(n.get('server'), str) and not re.search(r'[\s,#/]', n['server']), 'Invalid node server')
    require(type(n.get('port')) is int and 1 <= n['port'] <= 65535, 'Invalid node port')
    require(not n.get('dialer-proxy') and not n.get('interface-name'), 'Node has an existing dialer/interface binding; review it first')


def build_config(source, options, pool, device):
    """Pure transform, also used as the reference implementation for the JS extension."""
    require(isinstance(source, dict), 'Subscription must be a mapping')
    nodes = source.get('proxies') or []
    names = options['nodes']
    require(isinstance(names, list) and names and len(names) == len(set(names)), 'Select one or more distinct real nodes')
    selected = []
    for name in names:
        matches = [n for n in nodes if isinstance(n, dict) and n.get('name') == name]
        require(len(matches) == 1, 'Selected node missing or duplicate: ' + str(name))
        validate_node(matches[0])
        selected.append(copy.deepcopy(matches[0]))
    require(options['exit_mode'] in ['A', 'B'], 'Exit mode must be A or B')
    result = {k: copy.deepcopy(source[k]) for k in
              ['external-controller', 'external-controller-unix', 'secret', 'mixed-port'] if k in source}
    groups = []
    if options['exit_mode'] == 'A':
        require(len(selected) == 1, 'Mode A pins exactly one selected exit')
        groups.append({'name': GROUP, 'type': 'select', 'proxies': [selected[0]['name']]})
    else:
        residential = copy.deepcopy(options.get('residential'))
        validate_node(residential)
        require(residential['type'] == 'socks5' and residential['name'] not in names, 'Residential SOCKS5 required')
        residential.update({'udp': False, 'dialer-proxy': '跳板'})
        selected.append(residential)
        groups = [{'name': GROUP, 'type': 'select', 'proxies': [residential['name']]},
                  {'name': '跳板', 'type': 'select', 'proxies': names}]
    # Unless UDP has actually been verified, explicit rules reject overseas UDP.
    udp = options.get('udp_verified') is True and options['exit_mode'] == 'A'
    if not udp:
        for n in selected:
            n['udp'] = False
    overseas = domains(CLAUDE + options.get('overseas_domains', []))
    domestic = domains(options.get('direct_domains', []))
    require(not set(overseas) & set(domestic), 'Conflicting explicit domain policies')
    foreign_dns = ['https://1.1.1.1/dns-query#' + GROUP, 'https://8.8.8.8/dns-query#' + GROUP]
    local_dns = ['223.5.5.5#DIRECT', '119.29.29.29#DIRECT']
    policy = {('+.' + s): foreign_dns for s in overseas}
    for s in domestic:
        policy['+.' + s] = local_dns
    policy['geosite:bilibili'] = local_dns
    policy['rule-set:guard-wechat'] = local_dns
    policy['rule-set:guard-services'] = local_dns
    policy['geosite:geolocation-!cn'] = foreign_dns
    policy['rule-set:guard-direct'] = local_dns
    subnet = ipaddress.ip_network(pool)
    base = str(subnet.network_address + 1)
    result.update({
        'mode': 'rule', 'ipv6': False, 'allow-lan': False, 'log-level': 'info',
        'proxies': selected, 'proxy-groups': groups, 'proxy-providers': {},
        'geodata-mode': True, 'geo-auto-update': True, 'geo-update-interval': 24,
        'profile': {'store-selected': True, 'store-fake-ip': False},
        'tun': {'enable': True, 'device': device, 'stack': 'gvisor', 'mtu': 1500,
                'auto-route': True, 'strict-route': True, 'auto-detect-interface': True,
                'dns-mode': 'native', 'inet4-address': [base + '/30'],
                'dns-hijack': ['any:53', 'tcp://any:53']},
        'dns': {'enable': True, 'listen': '127.0.0.1:1053', 'ipv6': False,
                'enhanced-mode': 'fake-ip', 'fake-ip-range': base + '/16',
                'fake-ip-filter-mode': 'blacklist', 'fake-ip-filter': ['*.lan', '*.local'],
                'prefer-h3': False, 'respect-rules': False,
                'default-nameserver': ['223.5.5.5', '119.29.29.29'],
                'proxy-server-nameserver': local_dns, 'nameserver': foreign_dns,
                'nameserver-policy': policy, 'direct-nameserver': local_dns,
                'direct-nameserver-follow-policy': True},
        'rule-providers': {
            'guard-services': {'type': 'inline', 'behavior': 'classical',
                               'payload': ['DOMAIN-SUFFIX,' + x for x in domestic] + ['DOMAIN-KEYWORD,mirrorakam']}
        }})
    for name, url in PROVIDERS.items():
        result['rule-providers'][name] = {'type': 'http', 'behavior': PROVIDER_BEHAVIOR[name],
            'format': 'yaml', 'interval': 86400, 'url': url, 'path': './ruleset/' + name + '.yaml', 'proxy': GROUP}
    rules = []
    def overseas_rule(kind):
        if not udp:
            rules.append('AND,((NETWORK,udp),(' + kind + ')),REJECT')
        rules.append(kind + ',' + GROUP)
    for s in overseas:
        overseas_rule('DOMAIN-SUFFIX,' + s)
    for net in LAN4 + RESERVED:
        rules.append('IP-CIDR,' + net + ',DIRECT,no-resolve')
    for net in LAN6:
        rules.append('IP-CIDR6,' + net + ',DIRECT,no-resolve')
    rules += ['IP-CIDR6,::/0,REJECT,no-resolve', 'GEOSITE,bilibili,DIRECT',
              'RULE-SET,guard-wechat,DIRECT,no-resolve', 'RULE-SET,guard-services,DIRECT']
    overseas_rule('GEOSITE,geolocation-!cn')
    rules += ['RULE-SET,guard-direct,DIRECT', 'RULE-SET,guard-cncidr,DIRECT,no-resolve']
    if not udp:
        rules.append('NETWORK,udp,REJECT')
    rules.append('MATCH,' + GROUP)
    result['rules'] = rules
    return result


def extension(config, options):
    """Pin identity, but read rotated credentials from each subscription refresh."""
    fixed = copy.deepcopy(config)
    selected = fixed.pop('proxies')
    for k in ['external-controller', 'external-controller-unix', 'secret', 'mixed-port']:
        fixed.pop(k, None)
    identities = [{k: n[k] for k in ['name', 'type', 'server', 'port']} for n in selected if n['name'] in options['nodes']]
    residential = [n for n in selected if n['name'] not in options['nodes']]
    return '''// Generated by proxy-routing-guard; credentials stay in the subscription.
function main(config) {
  var fixed = %s;
  var identities = %s;
  var residential = %s;
  var old = (config && Array.isArray(config.proxies)) ? config.proxies : [];
  var nodes = [];
  var valid = true;
  identities.forEach(function(pin) {
    var found = old.filter(function(n) { return n && n.name === pin.name && n.type === pin.type && n.server === pin.server && Number(n.port) === pin.port && !n["dialer-proxy"] && !n["interface-name"]; });
    if(found.length !== 1) { valid = false; return; }
    var n = JSON.parse(JSON.stringify(found[0]));
    if(!%s) n.udp = false;
    nodes.push(n);
  });
  var out = {};
  ["external-controller", "external-controller-unix", "secret", "mixed-port"].forEach(function(k) {
    if(config && config[k] !== undefined) out[k] = config[k];
  });
  Object.keys(fixed).forEach(function(k) { out[k] = fixed[k]; });
  out.proxies = nodes.concat(residential);
  if(!valid) {
    out.proxies = [];
    out["proxy-groups"] = [{name: %s, type: "select", proxies: ["REJECT"]}];
    out["rule-providers"] = {};
    out.rules = ["MATCH,REJECT"];
  }
  return out;
}
''' % (json.dumps(fixed, ensure_ascii=False), json.dumps(identities, ensure_ascii=False),
       json.dumps(residential, ensure_ascii=False), json.dumps(options.get('udp_verified') is True and options['exit_mode'] == 'A'), json.dumps(GROUP, ensure_ascii=False))


def render_pf(tun='', ports=()):
    require(not tun or re.fullmatch(r'utun[0-9]{1,5}', tun), 'Invalid TUN interface')
    require(all(type(p) is int and 0 < p < 65536 for p in ports), 'Invalid proxy port')
    rules = ['table <guard_lan4> const { ' + ', '.join(LAN4) + ' }',
             'table <guard_lan6> const { ' + ', '.join(LAN6) + ' }']
    if not tun:
        for port in sorted(set(ports)):
            for family, destination in [('inet', '127.0.0.0/8'), ('inet6', '::1')]:
                rules.append('block return out quick on lo0 %s proto { tcp udp } to %s port %s user != 0 label "clash-guard:local-proxy"' % (family, destination, port))
    rules.append('pass out quick on lo0 all no state label "clash-guard:loopback"')
    if tun:
        rules.append('pass out quick on %s all no state label "clash-guard:tun"' % tun)
    rules += [
        'pass out quick proto { tcp udp } all user 0 flags any no state label "clash-guard:root"',
        'block drop out quick proto { tcp udp } to any port 53 label "clash-guard:dns"',
        'pass out quick inet to <guard_lan4> no state label "clash-guard:lan4"',
        'pass out quick inet6 to <guard_lan6> no state label "clash-guard:lan6"',
        'pass out quick inet proto udp from any port 68 to 255.255.255.255 port 67 no state label "clash-guard:dhcp4"',
        'pass out quick inet6 proto udp from any port 546 to ff02::1:2 port 547 no state label "clash-guard:dhcp6"',
        'pass out quick inet6 proto icmp6 to ff02::/16 icmp6-type { 133 135 136 } no state label "clash-guard:ndp"',
        'block drop out quick all label "clash-guard:block"']
    return '\n'.join(rules) + '\n'


def switch_decision(gui, intent_tun, intent_proxy, actual_tun, valid, native_both, native_exit):
    # A failed health request or node timeout is deliberately absent from this state machine.
    if not gui:
        return 'native' if native_exit else 'restricted'
    if not valid:
        return 'restricted'
    if native_both and intent_tun is False and intent_proxy is False and actual_tun is False:
        return 'native'
    return 'guarding' if intent_tun is True and actual_tun is True else 'restricted'


def restore_steps(steps, log):
    """Each recovery step runs even if previous steps failed."""
    errors = []
    for name, action in steps:
        try:
            action()
            log(name + ': ok')
        except Exception as e:
            errors.append(name + ': ' + str(e))
            log(errors[-1])
    return errors
