"""Linux node transaction. Executed only by a user-owned SSH session; no import side effects."""
import argparse
import base64
import contextlib
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
import zipfile

ROOT = Path('/var/lib/proxy-routing-guard-vps')
INSTALL = Path('/opt/proxy-routing-guard-node')
UNIT = 'proxy-guard-node.service'
UNITS = Path('/etc/systemd/system')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
API = 'https://api.github.com/repos/XTLS/Xray-core/releases/latest'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def call(args, check=True, timeout=40):
    print(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()) + ' ' + Path(str(args[0])).name + ' ' + (str(args[1]) if len(args) > 1 else ''), flush=True)
    p = subprocess.run([str(x) for x in args], capture_output=True, text=True, env=ENV, timeout=timeout)
    need(not check or p.returncode == 0, '%s failed (exit %s)' % (Path(str(args[0])).name, p.returncode))
    return p


def write(path, value, mode=0o600):
    path = Path(path)
    need(not path.is_symlink(), 'Symlink destination rejected')
    temp = path.with_name('.' + path.name + '.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as f:
        f.write(value if isinstance(value, str) else json.dumps(value, indent=2) + '\n')
        f.flush(); os.fsync(f.fileno())
    os.chmod(temp, mode)
    os.replace(temp, path)


def read(path):
    return json.loads(Path(path).read_text())


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def private_root(path):
    p = Path(path)
    for q in [p] + list(p.parents):
        st = q.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022, 'Unsafe privileged directory')


def fetch(url, limit=2 * 1024 * 1024):
    need(url.startswith(('https://api.github.com/', 'https://github.com/XTLS/Xray-core/releases/download/')), 'Untrusted download URL')
    req = urllib.request.Request(url, headers={'User-Agent': 'proxy-routing-guard'})
    with urllib.request.urlopen(req, timeout=45) as r:
        need(r.geturl().startswith('https://'), 'Non-HTTPS redirect rejected')
        data = r.read(limit + 1)
    need(len(data) <= limit, 'Download too large')
    return data


def release(arch):
    data = json.loads(fetch(API))
    tag = data.get('tag_name', '')
    need(re.fullmatch(r'v[0-9.]+', tag) and not data.get('prerelease'), 'Unexpected release metadata')
    name = {'x86_64': 'Xray-linux-64.zip', 'aarch64': 'Xray-linux-arm64-v8a.zip'}[arch]
    assets = {a['name']: a for a in data['assets']}
    asset = assets[name]
    url = 'https://github.com/XTLS/Xray-core/releases/download/' + tag + '/' + name
    need(asset['browser_download_url'] == url, 'Unexpected release asset URL')
    dg = asset.get('digest') or ''
    if re.fullmatch(r'sha256:[0-9a-f]{64}', dg):
        checksum = dg.split(':')[1]
    else:
        sums = fetch(url + '.dgst').decode()
        match = re.search(r'(?im)^SHA2?-?256\s*(?:\([^\n]*\))?\s*[:=]\s*([0-9a-f]{64})\s*$', sums)
        need(match, 'Official SHA256 is unavailable; do not install an unverified binary')
        checksum = match.group(1).lower()
    return {'tag': tag, 'url': url, 'sha256': checksum, 'asset': name}


def firewall(port):
    need(not (shutil.which('firewall-cmd') and call(['firewall-cmd', '--state'], False).returncode == 0), 'Active firewalld is not supported')
    ufw = shutil.which('ufw')
    if ufw and 'Status: active' in call([ufw, 'status']).stdout:
        text = call([ufw, 'status', 'numbered']).stdout
        need(not re.search(r'(?<!\d)' + str(port) + r'(?!\d)', text), 'Chosen port already has a UFW rule; choose another port')
        return {'mode': 'ufw', 'rules_sha256': hashlib.sha256(text.encode()).hexdigest()}
    # Never assume an unknown/custom host firewall is empty.
    need(shutil.which('nft') or shutil.which('iptables-save'), 'Cannot inspect host firewall: install an inspection tool first')
    if shutil.which('nft'):
        need(not call(['nft', 'list', 'ruleset']).stdout.strip(), 'Custom nftables rules require manual review')
    for binary in ['iptables-save', 'ip6tables-save']:
        if shutil.which(binary):
            text = call([binary]).stdout
            need(not re.search(r'^-A |^:\S+ (?:DROP|REJECT)', text, re.M), 'Custom iptables rules require manual review')
    return {'mode': 'none'}


def inspect(port):
    need(os.geteuid() == 0 and platform.system() == 'Linux', 'Inspection requires Linux administrator read access')
    need(sys.version_info >= (3, 9), 'Python 3.9+ is required; install it before using this adapter')
    need(1024 <= port <= 65535, 'Node port must be unprivileged')
    osdata = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    distro = osdata.get('ID', '').strip('"')
    need(distro in ['debian', 'ubuntu'], 'Only Debian/Ubuntu are supported by this adapter')
    arch = platform.machine()
    need(arch in ['x86_64', 'aarch64'], 'Unsupported architecture')
    for cmd in ['systemctl', 'systemd-run', 'systemd-analyze', 'ss', 'python3']:
        need(shutil.which(cmd), 'Missing required command: ' + cmd)
    need(Path('/run/systemd/system').is_dir(), 'systemd is not running')
    version = int(call(['systemctl', '--version']).stdout.split()[1])
    need(version >= 247, 'systemd 247+ is required for private service credentials')
    need(not INSTALL.exists() and not INSTALL.is_symlink() and not (UNITS / UNIT).exists() and not (UNITS / UNIT).is_symlink(), 'Managed node already exists; use repair/restore, not fresh deployment')
    need(call(['systemctl', 'show', UNIT, '-p', 'LoadState', '--value']).stdout.strip() == 'not-found', 'Service name already exists')
    listeners = call(['ss', '-H', '-lntup']).stdout
    need(not re.search(r':' + str(port) + r'\s', listeners), 'Node port is already occupied')
    need(shutil.disk_usage('/opt').free > 300 * 1024 * 1024, 'Insufficient free space')
    return {'os': distro, 'arch': arch, 'systemd': version, 'port': port, 'firewall': firewall(port)}


def config(plan):
    return {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '0.0.0.0', 'port': plan['port'],
            'protocol': 'shadowsocks', 'settings': {'method': '2022-blake3-aes-128-gcm',
            'password': plan['password'], 'network': 'tcp'}}],
            'outbounds': [{'tag': 'internet', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}},
                          {'tag': 'deny', 'protocol': 'blackhole'}],
            'routing': {'domainStrategy': 'IPOnDemand', 'rules': [
                {'type': 'field', 'network': 'udp', 'outboundTag': 'deny'},
                {'type': 'field', 'ip': ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                    '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15',
                    '224.0.0.0/4', '240.0.0.0/4', '::/0'], 'outboundTag': 'deny'}]}}


def service_text():
    return '''[Unit]
Description=Proxy Routing Guard private node
After=network-online.target
Wants=network-online.target
[Service]
DynamicUser=yes
LoadCredential=node.json:/opt/proxy-routing-guard-node/config.json
ExecStart=/opt/proxy-routing-guard-node/xray run -config %d/node.json
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077
[Install]
WantedBy=multi-user.target
'''


def transaction_id(value):
    need(re.fullmatch(r'[0-9a-f]{24}', value), 'Invalid transaction ID')
    return value


def validate_plan(p):
    transaction_id(p['id'])
    need(type(p['port']) is int and 1024 <= p['port'] <= 65535, 'Invalid node port')
    need(len(base64.b64decode(p['password'], validate=True)) == 16, 'Invalid SS2022 key')
    r = p['release']
    need(re.fullmatch(r'v[0-9.]+', r['tag']), 'Invalid release tag')
    need(r['asset'] in ['Xray-linux-64.zip', 'Xray-linux-arm64-v8a.zip'], 'Invalid asset')
    need(r['url'] == 'https://github.com/XTLS/Xray-core/releases/download/' + r['tag'] + '/' + r['asset'], 'Release URL mismatch')
    need(re.fullmatch('[0-9a-f]{64}', r['sha256']), 'Missing pinned checksum')
    need(p.get('approved') is True, 'Server plan has not been approved')


@contextlib.contextmanager
def lock():
    ROOT.mkdir(mode=0o700, exist_ok=True)
    private_root(ROOT)
    with open(ROOT / 'transaction.lock', 'a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def status(bundle, phase, **kw):
    write(bundle / 'status.json', dict(phase=phase, time=time.time(), **kw))
    print('NODE phase=' + phase, flush=True)


def rollback_name(id):
    return 'proxy-guard-rollback-' + id


def timer_text(id, deadline):
    calendar = datetime.datetime.fromtimestamp(deadline, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    return ('[Unit]\nDescription=Proxy node recovery deadline\n[Timer]\nOnCalendar=' + calendar +
            '\nPersistent=true\nUnit=' + rollback_name(id) + '.service\n[Install]\nWantedBy=timers.target\n')


def job(id):
    return 'proxy-guard-install-' + id


def bootstrap(upload):
    upload = Path(upload)
    plan = read(upload / 'plan.json'); validate_plan(plan)
    need(upload == Path('/tmp/proxy-guard-' + plan['id']), 'Unexpected upload path')
    with lock():
        target = ROOT / plan['id']
        need(not target.exists(), 'Transaction already exists; inspect its report, do not rerun')
        need(not (ROOT / 'current.json').exists(), 'A managed node transaction still owns the server paths; inspect/restore it first')
        need(not any(read(p).get('phase') in ['prepared', 'installing', 'ready'] for p in ROOT.glob('*/status.json')), 'Another node transaction is active')
        # Treat user-writable upload as untrusted. Copy bytes, revalidate root-owned copy.
        target.mkdir(mode=0o700)
        for name in ['plan.json', 'vps_remote.py']:
            p = upload / name
            need(p.is_file() and not p.is_symlink() and p.stat().st_size < 256 * 1024, 'Unsafe upload')
            write(target / name, p.read_text())
        plan = read(target / 'plan.json'); validate_plan(plan)
        need(plan['id'] == target.name, 'Plan changed during upload')
        need(digest(target / 'vps_remote.py') == plan['engine_sha256'], 'Remote engine changed during upload')
        facts = inspect(plan['port'])
        need(facts == plan['baseline'], 'Server changed since inspection; prepare a new plan')
        write(target / 'original.json', {'facts': facts, 'node_paths_absent': True, 'time': time.time()})
        write(target / 'restore.sh', '#!/bin/sh\nset -u\nexec /usr/bin/python3 -I -B "' + str(target / 'vps_remote.py') + '" restore ' + plan['id'] + '\n', 0o700)
        write(target / 'COMPLETE', 'backup complete\n')
        write(ROOT / 'current.json', {'id': plan['id']})
        rb = rollback_name(plan['id'])
        write(UNITS / (rb + '.service'), '[Unit]\nDescription=Proxy node recovery lease\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -I -B ' + str(target / 'vps_remote.py') + ' recover ' + plan['id'] + '\n')
        deadline = time.time() + 900
        write(UNITS / (rb + '.timer'), timer_text(plan['id'], deadline))
        status(target, 'prepared', deadline=deadline)
        call(['systemctl', 'daemon-reload'])
        call(['systemctl', 'enable', '--now', rb + '.timer'])
        need(call(['systemctl', 'is-active', rb + '.timer'], False).returncode == 0, 'Recovery timer failed')
        try:
            call(['systemd-run', '--unit=' + job(plan['id']), '--property=Type=oneshot', '--property=TimeoutStartSec=600', '--property=TimeoutStopSec=15',
                  '--property=KillMode=control-group', '--property=OnFailure=' + rb + '.service',
                  '/usr/bin/python3', '-I', '-B', str(target / 'vps_remote.py'), 'apply', plan['id']])
        except Exception:
            # Recovery lease remains armed even if systemd-run does not start.
            raise RuntimeError('Install job did not start; recovery lease remains armed')


def apply(id):
    b = ROOT / id
    with lock():
        p = read(b / 'plan.json'); validate_plan(p)
        need(read(ROOT / 'current.json')['id'] == id, 'Server path ownership changed')
        state = read(b / 'status.json')
        need(state['phase'] == 'prepared' and time.time() < state['deadline'], 'Expired or already used transaction')
        need((b / 'COMPLETE').is_file(), 'Backup incomplete')
        status(b, 'installing', deadline=state['deadline'])
        try:
            need(inspect(p['port']) == p['baseline'], 'Server baseline changed before install')
            data = fetch(p['release']['url'], 100 * 1024 * 1024)
            archive = b / 'xray.zip'; archive.write_bytes(data)
            need(digest(archive) == p['release']['sha256'], 'Release checksum mismatch')
            stage = b / 'node'; stage.mkdir(mode=0o755)
            with zipfile.ZipFile(archive) as z:
                matches = [i for i in z.infolist() if i.filename == 'xray']
                need(len(matches) == 1, 'Missing/duplicate binary in archive')
                member = matches[0]
                need(member.file_size < 150 * 1024 * 1024 and not stat.S_ISLNK(member.external_attr >> 16), 'Unsafe archive entry')
                (stage / 'xray').write_bytes(z.read(member))
            os.chmod(stage / 'xray', 0o755)
            write(stage / 'config.json', config(p))
            call([stage / 'xray', 'run', '-test', '-config', stage / 'config.json'])
            write(b / UNIT, service_text(), 0o644)
            # Verify using the staged executable, before creating live service paths.
            write(b / UNIT, service_text().replace('/opt/proxy-routing-guard-node/xray', str(stage / 'xray')), 0o644)
            call(['systemd-analyze', 'verify', b / UNIT])
            write(b / UNIT, service_text(), 0o644)
            need(not INSTALL.exists(), 'Node path appeared during preparation')
            # Mark ownership before mutation so recovery also handles a partial copy.
            write(b / 'MUTATING', 'owned new paths only\n')
            shutil.copytree(stage, INSTALL)
            shutil.copyfile(b / UNIT, UNITS / UNIT); os.chmod(UNITS / UNIT, 0o644)
            if p['baseline']['firewall']['mode'] == 'ufw':
                write(b / 'UFW-OWNED', 'rule may have been created\n')
                call(['ufw', 'allow', str(p['port']) + '/tcp', 'comment', 'proxy-guard-' + id])
            call(['systemctl', 'daemon-reload'])
            call(['systemctl', 'start', UNIT])
            verify_service(p)
            status(b, 'ready', deadline=state['deadline'])
        except Exception as e:
            status(b, 'failed', error=str(e))
            raise


def verify_service(p):
    end = time.monotonic() + 20
    while time.monotonic() < end:
        if call(['systemctl', 'is-active', UNIT], False).returncode == 0:
            pid = call(['systemctl', 'show', UNIT, '-p', 'MainPID', '--value']).stdout.strip()
            listeners = call(['ss', '-H', '-lntp']).stdout.splitlines()
            if pid.isdigit() and int(pid) > 0 and any(re.search(r':' + str(p['port']) + r'\s', line) and
                    re.search(r'\bpid=' + pid + r'\b', line) for line in listeners):
                return
        time.sleep(1)
    raise RuntimeError('Node listener was not verified as owned by the service MainPID')


def commit(id):
    b = ROOT / id
    with lock():
        p = read(b / 'plan.json'); state = read(b / 'status.json')
        need(state['phase'] == 'ready' and time.time() < state['deadline'], 'Node lease expired or deployment was not ready')
        need(read(ROOT / 'current.json')['id'] == id, 'Server path ownership changed')
        verify_service(p)
        call(['systemctl', 'enable', UNIT])
        status(b, 'committed')
        call(['systemctl', 'disable', '--now', rollback_name(id) + '.timer'])


def restore(id, lease=False):
    b = ROOT / id
    # Stop the whole install cgroup BEFORE obtaining the mutation lock.
    # Committed lease callbacks do nothing; explicit restore still removes the node.
    with lock():
        phase = read(b / 'status.json')['phase']
        if phase == 'restored':
            current = ROOT / 'current.json'
            if current.exists() and read(current)['id'] == id:
                current.unlink()
            return
        if lease and phase == 'committed':
            return
        need(read(ROOT / 'current.json')['id'] == id, 'This restore does not own the current node; no changes made')
    call(['systemctl', 'stop', job(id) + '.service'], False)
    with lock():
        phase = read(b / 'status.json')['phase']
        if phase == 'restored' or (lease and phase == 'committed'):
            return
        need(read(ROOT / 'current.json')['id'] == id, 'Server ownership changed while stopping install')
        job_state = call(['systemctl', 'is-active', job(id) + '.service'], False).stdout.strip()
        need(job_state in ['inactive', 'failed', 'unknown'], 'Install cgroup is still active; recovery will not race it')
        errors = []
        def step(label, fn):
            try:
                fn()
            except Exception as e:
                errors.append(label + ': ' + str(e))
        p = read(b / 'plan.json')
        if (b / 'MUTATING').exists():
            step('stop node', lambda: call(['systemctl', 'disable', '--now', UNIT]))
            # Never remove files while the service still has a live process.
            active = call(['systemctl', 'is-active', UNIT], False).stdout.strip()
            if active not in ['inactive', 'failed', 'unknown']:
                errors.append('node still active; its files were retained')
            else:
                step('remove unit', lambda: (UNITS / UNIT).unlink(missing_ok=True))
                step('remove node files', lambda: shutil.rmtree(INSTALL) if INSTALL.exists() else None)
        if (b / 'UFW-OWNED').exists():
            step('remove owned UFW rule', lambda: call(['ufw', '--force', 'delete', 'allow', str(p['port']) + '/tcp', 'comment', 'proxy-guard-' + id]))
        rb = rollback_name(id)
        step('disable lease', lambda: call(['systemctl', 'disable', '--now', rb + '.timer']))
        for suffix in ['timer', 'service']:
            step('remove lease ' + suffix, lambda suffix=suffix: (UNITS / (rb + '.' + suffix)).unlink(missing_ok=True))
        step('reload systemd', lambda: call(['systemctl', 'daemon-reload']))
        status(b, 'restore_failed' if errors else 'restored', errors=errors)
        if not errors:
            (ROOT / 'current.json').unlink()
        need(not errors, 'Recovery incomplete; inspect status.json')


def export(path, value):
    # Export only nonsecret reports into the user's private upload directory.
    uid = int(os.environ.get('SUDO_UID', '0')); gid = int(os.environ.get('SUDO_GID', '0'))
    parent = Path(path).parent
    need(parent.parent == Path('/tmp') and re.fullmatch(r'proxy-guard-[0-9a-f]{24}', parent.name), 'Unexpected report directory')
    if not parent.exists():
        parent.mkdir(mode=0o700); os.chown(parent, uid, gid)
    st = parent.lstat()
    need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and st.st_uid in [0, uid] and not st.st_mode & 0o077,
         'Report directory is not private or has unexpected ownership')
    write(path, value)
    os.chown(path, uid, gid)


def wait_ready(upload):
    id = transaction_id(read(Path(upload) / 'plan.json')['id'])
    for _ in range(220):
        state = read(ROOT / id / 'status.json')
        if state['phase'] not in ['prepared', 'installing']:
            export(Path(upload) / 'status.json', state)
            need(state['phase'] == 'ready', 'Install job failed; recovery is automatic. Inspect the server journal and status.json')
            return
        time.sleep(3)
    raise RuntimeError('Install job timed out; recovery lease remains armed')


def main():
    a = argparse.ArgumentParser(); a.add_argument('action', choices=['inspect', 'bootstrap', 'apply', 'commit', 'restore', 'recover', 'status', 'diagnose'])
    a.add_argument('target'); a.add_argument('--port', type=int); args = a.parse_args()
    need(os.geteuid() == 0, 'Run from your SSH terminal with sudo; do not send the password to the agent')
    if args.action == 'inspect':
        facts = inspect(args.port)
        export(Path(args.target) / 'inspection.json', {'baseline': facts, 'release': release(facts['arch']), 'time': time.time()})
    elif args.action == 'bootstrap':
        bootstrap(args.target)
        wait_ready(args.target)
    else:
        id = transaction_id(args.target)
        private_root(ROOT / id)
        if args.action == 'status':
            export(Path('/tmp/proxy-guard-' + id) / 'status.json', read(ROOT / id / 'status.json'))
        elif args.action == 'diagnose':
            logs = {}
            for unit in [job(id) + '.service', rollback_name(id) + '.service', UNIT]:
                logs[unit] = call(['journalctl', '--no-pager', '-n', '150', '-u', unit], False).stdout
            export(Path('/tmp/proxy-guard-' + id) / 'diagnostics.json', {'status': read(ROOT / id / 'status.json'), 'journal': logs, 'time': time.time()})
        elif args.action == 'apply':
            apply(id)
        elif args.action == 'commit':
            commit(id)
        else:
            restore(id, args.action == 'recover')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('NODE ERROR: ' + str(e), file=sys.stderr)
        sys.exit(1)
