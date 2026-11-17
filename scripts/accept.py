"""Evidence-producing acceptance. Missing evidence is never converted to a pass."""
import contextlib
import json
import os
from pathlib import Path
import secrets
import threading
import time
import urllib.parse
import uuid

from guardlib import *
from macos import *


class Capture:
    def __init__(self, settings, output):
        self.s, self.path = settings, Path(output)
        self.lines = []
        self.stop = threading.Event()
        self.started = threading.Event()
        self.error = ''

    def __enter__(self):
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.thread.start()
        require(self.started.wait(6), 'Core log capture did not start')
        require(not self.error, 'Core logs unavailable: ' + self.error)
        return self

    def collect(self):
        connection = UnixHTTP(self.s['api_socket'], timeout=3)
        self.connection = connection
        try:
            headers = {'Authorization': 'Bearer ' + self.s['api_secret']} if self.s.get('api_secret') else {}
            connection.request('GET', '/logs?level=debug', headers=headers)
            response = connection.getresponse()
            require(response.status == 200, 'Log stream HTTP ' + str(response.status))
            connection.sock.settimeout(240)
            self.started.set()
            with open(self.path, 'a', buffering=1) as f:
                os.chmod(self.path, 0o600)
                while not self.stop.is_set():
                    line = response.readline(65536)
                    if not line:
                        break
                    value = json.loads(line)
                    message = value.get('payload') or value.get('message') or ''
                    # Retain only routing/DNS events, no arbitrary config or HTTP bodies.
                    if any(token in message for token in ['[TCP]', '[UDP]', '[DNS]', 'match ', 'using ']):
                        self.lines.append(message)
                        f.write(json.dumps({'time': time.time(), 'message': message}, ensure_ascii=False) + '\n')
        except Exception as e:
            if not self.stop.is_set():
                self.error = str(e)
                self.started.set()
        finally:
            connection.close()

    def __exit__(self, *args):
        self.stop.set()
        with contextlib.suppress(Exception):
            self.connection.sock.shutdown(socket.SHUT_RDWR)
        self.thread.join(4)

    def route(self, host, target, since=0):
        lines = self.lines[since:]
        matches = [line for line in lines if host in line and ('[TCP]' in line or '[UDP]' in line)
                   and 'using ' in line and target in line.split('using ', 1)[1]]
        return matches[-5:]


def status(ok, **data):
    return dict(status='pass' if ok else 'fail', **data)


def direct_acceptance(s, trace):
    tests = domestic_tests(s['options'])
    results = []
    for url in tests['urls'] + [tests['ip_url']]:
        begin = len(trace.lines)
        probe = curl_probe(s, url)
        time.sleep(.3)
        probe['routing_evidence'] = trace.route(urllib.parse.urlsplit(url).hostname, 'DIRECT', begin)
        results.append(probe)
    okay = (all(r['reachable'] and 200 <= r['http'] < 400 and r['routing_evidence'] for r in results)
            and 200 <= results[-1]['http'] < 300 and results[-1]['ip'] == tests['expected_ip'])
    return status(okay, probes=results, expected_native_ip=tests['expected_ip'],
                  note='Targets and native exit region were verified before deployment; no domestic endpoints are bundled')


def dns_leak_scan(s):
    """Public site's documented-by-frontend Standard test protocol, not guessed isp.ac JSON."""
    base = 'https://www.dnsleaktest.com'
    def post(path, value):
        p = user_run(s, ['/usr/bin/curl', '-q', '--noproxy', '*', '--silent', '--show-error', '--fail',
                        '--connect-timeout', '5', '--max-time', '15', '--max-filesize', '131072',
                        '-H', 'Content-Type: application/json', '--data-binary', json.dumps(value), base + path], timeout=18)
        return json.loads(p.stdout)
    ids = [str(uuid.uuid4()) for _ in range(6)]
    result = {'provider': base, 'protocol_source': base + '/assets/js/app.js', 'pass': False, 'servers': []}
    try:
        post('/api/v1/identifiers', {'identifiers': ids})
        for value in ids:
            # A TLS hostname failure can still follow a valid DNS query; never disable certificate checking.
            curl_probe(s, 'https://' + value + '.test.dnsleaktest.com', seconds=6)
        round_result = post('/api/v1/servers-for-round', {'queries': ids})
        servers = post('/api/v1/servers-for-result', {'queries': ids})
        require(isinstance(round_result, dict) and isinstance(round_result.get('count'), int), 'DNS test API round schema changed')
        require(isinstance(servers, list) and servers, 'DNS test returned no resolvers')
        for row in servers:
            ip = str(ipaddress.ip_address(row['ip_address']))
            country = row.get('country_code')
            require(isinstance(country, str) and re.fullmatch('[A-Z]{2}', country), 'Unknown resolver country schema')
            result['servers'].append({'ip': ip, 'country': country, 'isp': row.get('isp', '')})
        result['pass'] = bool(result['servers']) and all(r['country'] not in ['CN', 'HK', 'MO'] for r in result['servers'])
    except Exception as e:
        result['error'] = str(e)
    return result


def runtime_checks(s, bundle):
    actual_tun(s)
    runtime = api(s, '/configs')
    effective = yaml_read(Path(s['config_dir']) / 'clash-verge.yaml')
    expected = read_json(bundle / 'stage/candidate.json')
    require(isinstance(effective, dict), 'Effective runtime configuration unavailable')
    for key in ['rules', 'proxy-groups', 'rule-providers', 'dns']:
        require(effective.get(key) == expected.get(key), 'Effective configuration differs: ' + key)
    groups = api(s, '/proxies').get('proxies', {})
    for group in expected['proxy-groups']:
        actual = groups.get(group['name'], {})
        require(actual.get('type', '').lower() == 'selector' and actual.get('all') == group['proxies'], 'Runtime manual group differs: ' + group['name'])
        require(actual.get('now') in group['proxies'], 'Unexpected selected exit')
    rules = api(s, '/rules').get('rules', [])
    require(len(rules) == len(expected['rules']) and rules[-1].get('proxy') == GROUP and rules[-1].get('type', '').lower() == 'match', 'Runtime fallback/order differs')
    # Verify every rule type + target; compare the payload for ordinary rules.
    for actual, rule in zip(rules, expected['rules']):
        kind = rule.split(',', 1)[0]
        wanted_type = re.sub('[^a-z]', '', kind.lower())
        require(re.sub('[^a-z]', '', actual.get('type', '').lower()) == wanted_type, 'Runtime rule type/order mismatch')
        target = rule.rsplit(',', 1)[-1]
        if target == 'no-resolve':
            target = rule.rsplit(',', 2)[-2]
        require(actual.get('proxy') == target, 'Runtime rule action differs')
        require(not actual.get('extra', {}).get('disabled', False), 'A runtime routing rule is disabled')
        if kind == 'AND':
            text = rule[len('AND,'):].rsplit(',', 1)[0].replace('),(', ')&&(')
            normalize = lambda v: re.sub(r'[\s-]', '', v).lower()
            require(normalize(actual.get('payload', '')) == normalize(text), 'Runtime AND rule condition differs')
        if kind not in ['AND', 'MATCH']:
            require(str(actual.get('payload', '')).lower() == rule.split(',')[1].lower(), 'Runtime rule payload differs')
    verify_subscription_files(s, bundle)
    prefs = yaml_read(Path(s['config_dir']) / 'verge.yaml')
    require(prefs.get('enable_auto_launch') is True and Path(s['login_path']).is_file(), 'Auto launch not enabled')
    require(prefs.get('enable_dns_settings') is False, 'Client DNS override is still enabled')
    launch = run(['/bin/launchctl', 'print', 'gui/%s/%s' % (s['uid'], CLIENT_ID)], check=False)
    require(launch.returncode == 0, 'Login LaunchAgent is not registered')
    require(runtime.get('mode') == 'rule' and runtime.get('ipv6') is False and effective['dns']['ipv6'] is False, 'Mode/IPv6 differs')
    dns = user_run(s, ['/usr/bin/dig', '@' + s['tun_dns'], 'claude.ai', 'AAAA', '+short', '+time=3', '+tries=1'], check=False)
    require(dns.returncode == 0 and not dns.stdout.strip(), 'DNS AAAA was not suppressed')
    for service in s['services']:
        network = network_snapshot()[service]
        require(network['dns'] == [s['tun_dns']], 'System DNS does not point at TUN')
        require(network['http'].get('Enabled') == 'Yes' and network['http'].get('Server') == '127.0.0.1' and int(network['http'].get('Port', 0)) == s['mixed_port'], 'System proxy differs')
    return {'mode': runtime['mode'], 'tun': s['device'], 'dns_ipv6': False, 'boot_test': 'not_tested', 'bare_ipv6_test': 'not_tested'}


def network_acceptance(s, bundle):
    report = {'items': {}, 'uid': s['uid'], 'time': time.time(), 'gate_passed': False,
              'limits': ['HTTP response proves transport only; login/page functionality is separate',
                         'No reboot, existing WebSocket or browser background-connection test is claimed']}
    items = report['items']
    try:
        domestic_tests(s['options'])
    except (GuardError, ValueError) as e:
        items.update({str(i): {'status': 'not_tested'} for i in range(1, 7)})
        items['3'] = status(False, error=str(e))
        return report
    try:
        facts = runtime_checks(s, bundle)
        items['1'] = status(True, **facts)
        items['2'] = status(True, subscription_unchanged=True, manual_exit_only=True, fallback=GROUP)
    except Exception as e:
        items['1'] = status(False, error=str(e))
        items['2'] = status(False, error='Runtime policy check incomplete')
        return report
    old_level = api(s, '/configs').get('log-level', 'info')
    api(s, '/configs', 'PATCH', {'log-level': 'debug'})
    try:
        with Capture(s, bundle / 'network-core.jsonl') as trace:
            items['3'] = direct_acceptance(s, trace)
            foreign = []
            exceptions = s['options'].get('accepted_exceptions', {})
            for url in ['https://api.ipify.org', 'https://ipinfo.io/json', 'https://claude.ai',
                        'https://statsig.anthropic.com', 'https://httpbin.org/ip', 'https://www.googletagmanager.com']:
                begin = len(trace.lines)
                p = curl_probe(s, url)
                time.sleep(.3)
                host = urllib.parse.urlsplit(url).hostname
                p['routing_evidence'] = trace.route(host, GROUP, begin)
                p['pass'] = p['reachable'] and bool(p['routing_evidence'])
                if host == 'statsig.anthropic.com' and not p['pass'] and host in exceptions:
                    # No pass is invented: an explicit named exception is retained in the result.
                    p['accepted_exception'] = exceptions[host]
                foreign.append(p)
            ips = [r['ip'] for r in foreign if r['ip']]
            country = foreign[1]['country']
            exit_ok = len(ips) >= 3 and set(ips) == {s['options']['expected_exit_ip']} and country == s['options']['expected_exit_country']
            okay = exit_ok and all(r['pass'] or r.get('accepted_exception') for r in foreign)
            items['4'] = status(okay, probes=foreign, exit_consistent=exit_ok)
            if okay and any(r.get('accepted_exception') for r in foreign):
                items['4']['status'] = 'accepted_exception'
            dns_results = []
            for _ in range(3):
                host = 'guard-' + secrets.token_hex(6) + '.example.com'
                begin = len(trace.lines)
                # Explicit DoH JSON request, then a separate core DNS query. Inner DoH names are encrypted.
                url = 'https://cloudflare-dns.com/dns-query?' + urllib.parse.urlencode({'name': host, 'type': 'A'})
                p = user_run(s, ['/usr/bin/curl', '-q', '--noproxy', '*', '--silent', '--show-error', '--fail',
                                '--connect-timeout', '4', '--max-time', '10', '--max-filesize', '65536',
                                '-H', 'accept: application/dns-json', url], timeout=12, check=False)
                try:
                    answer = json.loads(p.stdout)
                    doh_ok = p.returncode == 0 and answer.get('Status') in [0, 3] and any(q.get('name', '').rstrip('.') == host for q in answer.get('Question', []))
                except (ValueError, TypeError):
                    doh_ok = False
                core_query_ok = False
                try:
                    answer = api(s, '/dns/query?' + urllib.parse.urlencode({'name': host, 'type': 'A'}), timeout=10)
                    core_query_ok = isinstance(answer, dict) and 'Status' in answer
                except Exception:
                    pass
                time.sleep(.4)
                events = [line for line in trace.lines[begin:] if host in line and '[DNS]' in line]
                route = trace.route('cloudflare-dns.com', GROUP, begin)
                dns_results.append({'name': host, 'doh_response': doh_ok, 'core_query': core_query_ok,
                                    'core_dns_events': events[-5:], 'doh_routing': route})
            external = curl_probe(s, 'https://isp.ac/dns-leak-test')
            scan = dns_leak_scan(s)
            okay = all(x['doh_response'] and x['core_query'] and x['core_dns_events'] and x['doh_routing'] for x in dns_results)
            items['5'] = status(False, random_queries=dns_results, original_endpoint=external, alternative_scan=scan,
                                reason='The original isp.ac API is not automatically certified; approval is required to substitute dnsleaktest.com')
            if okay and scan['pass'] and exceptions.get('external_dns_leak'):
                items['5'].update(status='accepted_exception', accepted_evidence=exceptions['external_dns_leak'])
            begin = len(trace.lines)
            bare = curl_probe(s, 'http://1.1.1.1')
            time.sleep(.3)
            bare['routing_evidence'] = trace.route('1.1.1.1:80', GROUP, begin)
            items['6'] = status(bare['reachable'] and bool(bare['routing_evidence']), probe=bare)
    except Exception as e:
        report['error'] = str(e)
    finally:
        with contextlib.suppress(Exception):
            api(s, '/configs', 'PATCH', {'log-level': old_level})
        for number in range(1, 7):
            items.setdefault(str(number), {'status': 'not_tested'})
        report['gate_passed'] = all(v['status'] in ['pass', 'accepted_exception'] for v in items.values())
    return report


def blocked_probes(s):
    # Raw addresses remove DNS failure as an explanation; cover ordinary TUN and local-proxy bypass.
    values = [curl_probe(s, u, seconds=5) for u in ['http://1.1.1.1', 'http://223.5.5.5', 'https://api.ipify.org']]
    values.append(curl_probe(s, 'https://api.ipify.org', seconds=5, explicit_proxy=True))
    return values, all(v['exit'] in [7, 28] and not v['reachable'] for v in values)


def blocked_packets(text):
    active, total = False, 0
    for line in text.splitlines():
        if re.match(r'^@?\d*\s*(block|pass|anchor)\b', line):
            active = 'clash-guard:block' in line or 'clash-guard:local-proxy' in line
        if active:
            m = re.search(r'Packets:\s*(\d+)', line)
            if m:
                total += int(m.group(1))
                active = False
    return total


def drills(s, bundle):
    from admin import check_guard, load_pf, log
    native_url = domestic_tests(s['options'])['urls'][0]
    report = {'items': {}, 'passed': False, 'uid': s['uid'], 'time': time.time()}
    settings = api(s, '/configs')
    runtime = yaml_read(Path(s['config_dir']) / 'clash-verge.yaml')
    saved_group = api(s, '/proxies/' + urllib.parse.quote(GROUP, safe='')).get('now')
    oldlevel = settings.get('log-level', 'info')
    api(s, '/configs', 'PATCH', {'log-level': 'debug'})
    try:
        # The temporary group has exactly one unreachable node. Nothing is added to subscriptions or saved selections.
        bad = copy.deepcopy(runtime)
        dead = {'name': 'guard-unreachable-test', 'type': 'socks5', 'server': '127.0.0.1', 'port': 1, 'udp': False}
        with socket.socket() as sock:
            require(sock.connect_ex(('127.0.0.1', 1)) != 0, 'Port 1 is unexpectedly listening; abort drill')
        bad['proxies'].append(dead)
        bad['proxy-groups'] = [dict(g, proxies=[dead['name']]) if g['name'] == GROUP else g for g in bad['proxy-groups']]
        with Capture(s, bundle / 'drill-9-core.jsonl') as trace:
            try:
                api(s, '/configs?force=true', 'PUT', {'payload': json.dumps(bad)}, timeout=20)
                checks = [curl_probe(s, u, seconds=6) for u in ['https://claude.ai', 'https://api.ipify.org']]
                domestic_begin = len(trace.lines)
                domestic = curl_probe(s, native_url, seconds=10)
                time.sleep(.3)
                group = api(s, '/proxies/' + urllib.parse.quote(GROUP, safe=''))
                domestic_trace = trace.route(urllib.parse.urlsplit(native_url).hostname, 'DIRECT', domestic_begin)
                foreign_traces = {h: [line for line in trace.lines if h in line and GROUP in line and dead['name'] in line]
                                  for h in ['claude.ai', 'api.ipify.org']}
                result = all(not x['reachable'] and x['exit'] != 0 for x in checks) and 200 <= domestic['http'] < 400 and bool(domestic_trace) and all(foreign_traces.values()) and group.get('all') == [dead['name']]
                report['items']['9'] = status(result, foreign=checks, domestic=domestic,
                    routing_evidence={'domestic': domestic_trace, 'foreign': foreign_traces})
            finally:
                api(s, '/configs?force=true', 'PUT', {'payload': json.dumps(runtime)}, timeout=20)
                api(s, '/proxies/' + urllib.parse.quote(GROUP, safe=''), 'PUT', {'name': saved_group})
                health(s, 120)
        require(report['items']['9']['status'] == 'pass', 'Bad-node drill failed; later drills skipped')
        try:
            # API-only failure leaves the saved UI intent on, distinguishing a fault from a user dual-off request.
            api(s, '/configs', 'PATCH', {'tun': {'enable': False}})
            time.sleep(3)
            before = blocked_packets(run(['/sbin/pfctl', '-a', ANCHOR, '-vvsr']).stdout)
            values, okay = blocked_probes(s)
            rules = run(['/sbin/pfctl', '-a', ANCHOR, '-vvsr']).stdout
            report['items']['10'] = status(okay and blocked_packets(rules) > before, probes=values,
                pf_counters=rules, existing_browser_connections='not_tested')
        finally:
            api(s, '/configs', 'PATCH', {'tun': runtime['tun']})
            health(s, 120)
            check_guard(s)
        require(report['items']['10']['status'] == 'pass', 'TUN-failure drill failed; exit drill skipped')
        try:
            stop_gui(s)
            time.sleep(3)
            if s['options']['native_on_gui_exit']:
                domestic = curl_probe(s, native_url)
                rules = run(['/sbin/pfctl', '-a', ANCHOR, '-sr']).stdout
                current = network_snapshot()
                clean = all(current[n]['dns'] != [s['tun_dns']] and current[n]['http'].get('Enabled') != 'Yes' for n in s['services'])
                report['items']['11'] = status(domestic['reachable'] and not rules.strip() and clean,
                    expected='native network after GUI exit, including crashes', domestic=domestic, strict_exit_block='not_applicable')
            else:
                before = blocked_packets(run(['/sbin/pfctl', '-a', ANCHOR, '-vvsr']).stdout)
                values, okay = blocked_probes(s)
                counters = run(['/sbin/pfctl', '-a', ANCHOR, '-vvsr']).stdout
                report['items']['11'] = status(okay and blocked_packets(counters) > before, expected='strict block', probes=values, pf_counters=counters)
        finally:
            install_login(s)
            open_gui(s)
            # GUI normally reapplies its saved TUN intent; perform one bounded API reload if it does not.
            time.sleep(3)
            api(s, '/configs', 'PATCH', {'tun': runtime['tun']})
            set_network(s)
            health(s, 120)
            check_guard(s)
        report['passed'] = all(r['status'] == 'pass' for r in report['items'].values())
    except Exception as e:
        report['error'] = str(e)
    finally:
        with contextlib.suppress(Exception):
            api(s, '/configs', 'PATCH', {'log-level': oldlevel})
        for number in ['9', '10', '11']:
            report['items'].setdefault(number, {'status': 'not_tested'})
        dump(bundle / 'drill.report.json', report)
    return report
