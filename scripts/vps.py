"""Bare VPS onboarding. Interactive SSH is run by the user in Terminal, never by the agent."""
import argparse
import base64
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guardlib import GuardError, require, atomic, dump, read_json, sha, run, validate_node, SAFE_ENV

SCRIPTS = Path(__file__).resolve().parent


def ssh_options(settings):
    # Default known_hosts is intentionally retained. Unknown fingerprints must be confirmed;
    # a changed fingerprint aborts. No sshpass, askpass or password command-line argument.
    return ['-o', 'StrictHostKeyChecking=ask', '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15',
            '-o', 'ServerAliveCountMax=3', '-o', 'ControlMaster=auto', '-o', 'ControlPersist=300',
            '-o', 'ControlPath=' + settings['control'], '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no']


def interactive(argv, timeout=900):
    require(sys.stdin.isatty(), 'This step requires your Terminal for SSH/sudo password input')
    env = dict(os.environ)
    for k in list(env):
        if k.lower().endswith('_proxy') or k in ['SSH_ASKPASS', 'SSH_ASKPASS_REQUIRE', 'PYTHONPATH', 'PYTHONHOME']:
            env.pop(k, None)
    # Password prompts inherit the terminal and are never captured in logs.
    p = subprocess.run(argv, env=env, timeout=timeout)
    require(p.returncode == 0, 'SSH step failed (exit %s); inspect this batch, do not blindly rerun' % p.returncode)


def remote(s, args, privileged=False, timeout=900):
    argv = list(map(str, args))
    if privileged and s['user'] != 'root':
        argv = ['sudo', '--'] + argv
    interactive(['/usr/bin/ssh'] + ssh_options(s) + ['-tt', '-p', str(s['ssh_port']),
                s['user'] + '@' + s['host'], shlex.join(argv)], timeout)


def transfer(s, local, name, upload=True):
    require(re.fullmatch('[a-zA-Z0-9_.-]+', name), 'Unsafe transfer name')
    dest = s['user'] + '@' + s['host'] + ':' + s['remote'] + '/' + name
    files = [str(local), dest] if upload else [dest, str(local)]
    interactive(['/usr/bin/scp'] + ssh_options(s) + ['-P', str(s['ssh_port'])] + files)


def entry(action):
    return '''#!/bin/sh
set -eu
umask 077
BASE=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P)
exec /usr/bin/python3 -I -B "$BASE/engine/vps.py" %s --bundle "$BASE"
''' % action


def init(host, ssh_port, user, port, name, output):
    require(os.geteuid() != 0, 'Run local preparation as the desktop user')
    require(ipaddress.ip_address(host).version == 4 and ipaddress.ip_address(host).is_global, 'Provide a public VPS IPv4 address')
    require(re.fullmatch('[a-z_][a-z0-9_-]{0,31}', user), 'Invalid SSH username')
    require(1 <= ssh_port <= 65535 and 1024 <= port <= 65535 and port != ssh_port, 'Invalid/conflicting SSH or node port')
    validate_node({'name': name, 'type': 'ss', 'server': host, 'port': port})
    b = Path(output).expanduser().absolute()
    require(not b.exists(), 'Use a fresh private output directory')
    b.mkdir(parents=True, mode=0o700); os.chmod(b, 0o700)
    engine = b / 'engine'; engine.mkdir(mode=0o700)
    for file in ['vps.py', 'vps_remote.py', 'guardlib.py']:
        shutil.copyfile(SCRIPTS / file, engine / file)
    id = os.urandom(12).hex()
    # Short path avoids macOS UNIX socket path length limits. Private, per transaction.
    control_dir = tempfile.mkdtemp(prefix='proxy-vps-', dir='/tmp')
    s = {'id': id, 'host': host, 'ssh_port': ssh_port, 'user': user, 'port': port, 'name': name,
         'remote': '/tmp/proxy-guard-' + id, 'control': control_dir + '/ctl'}
    dump(b / 'ssh.json', s)
    for action, file in [('inspect', 'connect-and-inspect.sh'), ('deploy', 'deploy-node.sh'), ('restore', 'restore-node.sh'), ('diagnose', 'collect-diagnostics.sh')]:
        atomic(b / file, entry(action), mode=0o700)
        run(['/bin/sh', '-n', b / file])
    return {'bundle': str(b), 'inspect': 'sh ' + shlex.quote(str(b / 'connect-and-inspect.sh')), 'live_changes': False}


def inspect(b):
    s = read_json(b / 'ssh.json')
    require(not (b / 'inspection.json').exists(), 'Inspection already exists; create a new batch if the server changed')
    remote(s, ['mkdir', '-m', '700', '--', s['remote']])
    transfer(s, b / 'engine/vps_remote.py', 'vps_remote.py')
    remote(s, ['/usr/bin/python3', '-I', '-B', s['remote'] + '/vps_remote.py', 'inspect', s['remote'], '--port', s['port']], True)
    transfer(s, b / 'inspection.json', 'inspection.json', False)
    os.chmod(b / 'inspection.json', 0o600)
    return read_json(b / 'inspection.json')


def prepare(b, approved, core):
    require(approved, 'Review the inspection and obtain user authorization before prepare')
    s = read_json(b / 'ssh.json'); report = read_json(b / 'inspection.json')
    require(time.time() - report['time'] < 86400, 'Inspection expired')
    require(report['baseline']['port'] == s['port'], 'Inspection port differs')
    require(not (b / 'plan.json').exists(), 'Plan exists; do not rotate credentials or reuse this transaction')
    core = Path(core).absolute()
    require(core.name == 'verge-mihomo' and core.is_file() and os.access(core, os.X_OK), 'Supply the discovered Clash Verge stable core executable')
    p = {'id': s['id'], 'port': s['port'], 'password': base64.b64encode(os.urandom(16)).decode(),
         'release': report['release'], 'baseline': report['baseline'], 'approved': True,
         'engine_sha256': sha(b / 'engine/vps_remote.py')}
    # Use the same validation as the remote worker, without any server mutation.
    from vps_remote import validate_plan
    validate_plan(p)
    dump(b / 'plan.json', p)
    dump(b / 'node.json', {'name': s['name'], 'type': 'ss', 'server': s['host'], 'port': s['port'],
         'cipher': '2022-blake3-aes-128-gcm', 'password': p['password'], 'udp': False})
    dump(b / 'local.json', {'core': str(core), 'core_sha256': sha(core)})
    atomic(b / 'PREPARED', 'ready\n')
    return {'deploy': 'sh ' + shlex.quote(str(b / 'deploy-node.sh')), 'restore_node': 'sh ' + shlex.quote(str(b / 'restore-node.sh')),
            'remote_restore': 'sudo sh /var/lib/proxy-routing-guard-vps/' + s['id'] + '/restore.sh',
            'node_credentials': 'private node.json; never print or paste it into chat'}


@contextlib.contextmanager
def isolated_proxy(core, node):
    """Explicit loopback probe only. No TUN, DNS listener, system settings or live client changes."""
    validate_node(node)
    with tempfile.TemporaryDirectory(prefix='proxy-node-test-') as folder:
        home = Path(folder)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        config = {'mixed-port': port, 'bind-address': '127.0.0.1', 'allow-lan': False, 'ipv6': False,
                  'mode': 'rule', 'log-level': 'silent', 'tun': {'enable': False}, 'dns': {'enable': False},
                  'proxies': [node], 'rules': ['MATCH,' + node['name']]}
        dump(home / 'config.json', config)
        run([str(core), '-t', '-d', str(home), '-f', str(home / 'config.json')], timeout=30)
        with open(home / 'core.log', 'w') as log:
            process = subprocess.Popen([str(core), '-d', str(home), '-f', str(home / 'config.json')],
                                       stdout=log, stderr=log, env=SAFE_ENV, start_new_session=True)
            try:
                for _ in range(100):
                    require(process.poll() is None, 'Isolated test core exited')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                            owner = run(['/usr/sbin/lsof', '-nP', '-a', '-p', str(process.pid),
                                         '-iTCP:' + str(port), '-sTCP:LISTEN', '-Fp'], check=False)
                            if 'p' + str(process.pid) in owner.stdout.splitlines():
                                break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise GuardError('Isolated proxy port did not start')
                yield port
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)


def probe(core, nodefile):
    node = read_json(nodefile)
    started = time.monotonic()
    with isolated_proxy(core, node) as port:
        args = ['/usr/bin/curl', '-q', '--silent', '--show-error', '--connect-timeout', '12', '--max-time', '30',
                '--proxy', 'http://127.0.0.1:' + str(port), '--noproxy', '', '--proto', '=https']
        ip = run(args + ['--fail', 'https://api.ipify.org'], timeout=35).stdout.strip()
        require(ipaddress.ip_address(ip).version == 4 and ipaddress.ip_address(ip).is_global, 'Node exit is not public IPv4')
        detail = json.loads(run(args + ['--fail', 'https://ipinfo.io/json'], timeout=35).stdout)
        require(detail.get('ip') == ip and re.fullmatch('[A-Z]{2}', detail.get('country', '')), 'Node exit measurements disagree')
        require(detail['country'] not in ['CN', 'HK', 'MO'], 'This node is not an eligible final exit')
        code = run(args + ['-o', '/dev/null', '-w', '%{http_code}', 'https://claude.ai'], timeout=35).stdout
        require(code.isdigit() and 200 <= int(code) < 500, 'Claude HTTPS transport failed')
    return {'node_sha256': sha(nodefile), 'time': time.time(), 'ip': ip, 'country': detail['country'],
            'claude_http': int(code), 'elapsed_ms': round((time.monotonic() - started) * 1000),
            'passed': True, 'scope': 'explicit proxy TCP only; not TUN/DNS/firewall acceptance'}


def deploy(b):
    s = read_json(b / 'ssh.json'); local = read_json(b / 'local.json')
    require((b / 'PREPARED').is_file() and not (b / 'ATTEMPTED').exists(), 'Missing prepared plan or already attempted; inspect logs instead of rerunning')
    require(sha(local['core']) == local['core_sha256'], 'Local core changed; prepare a new batch')
    atomic(b / 'ATTEMPTED', str(time.time()))
    remote_engine = s['remote'] + '/vps_remote.py'
    root_engine = '/var/lib/proxy-routing-guard-vps/' + s['id'] + '/vps_remote.py'
    transfer(s, b / 'plan.json', 'plan.json')
    try:
        remote(s, ['/usr/bin/python3', '-I', '-B', remote_engine, 'bootstrap', s['remote']], True)
        # Bootstrap waits for detached job completion and exports its nonsecret result.
        transfer(s, b / 'server-status.json', 'status.json', False)
        require(read_json(b / 'server-status.json')['phase'] == 'ready', 'Server did not reach ready state')
        proof = probe(local['core'], b / 'node.json')
        dump(b / 'node-evidence.json', proof)
        remote(s, ['/usr/bin/python3', '-I', '-B', root_engine, 'commit', s['id']], True)
        remote(s, ['/usr/bin/python3', '-I', '-B', root_engine, 'status', s['id']], True)
        transfer(s, b / 'server-status.json', 'status.json', False)
        require(read_json(b / 'server-status.json')['phase'] == 'committed', 'Server commit was not confirmed')
        atomic(b / 'COMMITTED', 'node verified; desktop deployment is separate\n')
        return proof
    except BaseException:
        dump(b / 'failure.json', {'time': time.time(), 'message': 'Deployment or validation failed; inspect remote status. Lease automatically removes uncommitted changes.'})
        # If communication is lost, the persistent systemd recovery timer is independent of SSH.
        try:
            remote(s, ['/usr/bin/python3', '-I', '-B', root_engine, 'recover', s['id']], True)
        except BaseException:
            pass
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__); sub = p.add_subparsers(dest='action', required=True)
    a = sub.add_parser('init'); a.add_argument('--host', required=True); a.add_argument('--ssh-port', type=int, default=22)
    a.add_argument('--user', default='root'); a.add_argument('--port', type=int, default=18443); a.add_argument('--name', default='VPS-Overseas'); a.add_argument('--output', required=True)
    for action in ['inspect', 'prepare', 'deploy', 'restore', 'diagnose', 'finish']:
        a = sub.add_parser(action); a.add_argument('--bundle', required=True)
        if action == 'prepare':
            a.add_argument('--approved', action='store_true'); a.add_argument('--core', required=True)
    a = p.parse_args()
    if a.action == 'init':
        result = init(a.host, a.ssh_port, a.user, a.port, a.name, a.output)
    else:
        b = Path(a.bundle).expanduser().absolute()
        if a.action == 'prepare':
            result = prepare(b, a.approved, a.core)
        elif a.action == 'inspect':
            result = inspect(b)
        elif a.action == 'deploy':
            result = deploy(b)
        elif a.action == 'diagnose':
            s = read_json(b / 'ssh.json')
            remote(s, ['/usr/bin/python3', '-I', '-B', '/var/lib/proxy-routing-guard-vps/' + s['id'] + '/vps_remote.py', 'diagnose', s['id']], True)
            transfer(s, b / 'diagnostics.json', 'diagnostics.json', False)
            os.chmod(b / 'diagnostics.json', 0o600)
            result = {'diagnostics': str(b / 'diagnostics.json')}
        elif a.action == 'finish':
            # A commit acknowledgment may be lost with SSH. Reconcile only from a
            # fresh user-collected server report and a new real node measurement.
            diag = read_json(b / 'diagnostics.json'); local = read_json(b / 'local.json')
            require(diag['status']['phase'] == 'committed' and 0 <= time.time() - diag['time'] < 300, 'Collect fresh committed server diagnostics first')
            require(sha(local['core']) == local['core_sha256'], 'Local core changed')
            result = probe(local['core'], b / 'node.json')
            dump(b / 'node-evidence.json', result); atomic(b / 'COMMITTED', 'verified after lost acknowledgment\n')
        else:
            s = read_json(b / 'ssh.json')
            remote(s, ['/usr/bin/python3', '-I', '-B', '/var/lib/proxy-routing-guard-vps/' + s['id'] + '/vps_remote.py', 'restore', s['id']], True)
            result = {'restored_node': True, 'desktop_unchanged': True}
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (GuardError, ValueError, OSError, subprocess.SubprocessError) as e:
        print('ERROR: ' + str(e), file=sys.stderr); sys.exit(1)
