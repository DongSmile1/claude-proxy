#!/usr/bin/env python3
"""User-invoked privileged transactions and the root-owned PF supervisor."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import plistlib
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guardlib import *
from macos import *

STORE = Path('/Library/Application Support/clash-guard-transactions')
STATE = Path('/var/run/clash-guard')
LOG = None


def log(message):
    line = time.strftime('%Y-%m-%dT%H:%M:%S%z') + ' ' + message
    try:
        print(line, flush=True)
    except (BrokenPipeError, OSError):
        pass  # A closed Terminal is not a reason to abandon the transaction.
    if LOG:
        with open(LOG, 'a') as f:
            f.write(line + '\n')


def verify_payload(bundle):
    require((bundle / 'PREPARED').is_file() and (bundle / 'original/COMPLETE').is_file(), 'Preparation/full backup incomplete')
    for relative, digest in read_json(bundle / 'payload-sha256.json').items():
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'Invalid manifest path')
        p = bundle / relative
        require(p.is_file() and not p.is_symlink() and sha(p) == digest, 'Payload/backup changed: ' + relative)


def bootstrap(action, source):
    require(os.geteuid() == 0 and sys.platform == 'darwin', 'Administrator macOS execution required')
    source = Path(source).absolute()
    verify_payload(source)
    s = read_json(source / 'settings.json')
    require(s['schema'] == SCHEMA and re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{6}', s['id']), 'Unknown transaction schema/id')
    require(s['uid'] > 0 and pwd.getpwnam(s['user']).pw_uid == s['uid'], 'Desktop identity changed')
    require(Path(s['home']).is_dir() and Path(s['config_dir']).parent == Path(s['home']) / 'Library/Application Support', 'Invalid target layout')
    require(Path(s['config_dir']).name == CLIENT_ID, 'Wrong client configuration directory')
    STORE.mkdir(mode=0o700, exist_ok=True)
    secure_root(STORE)
    destination = STORE / s['id']
    if not destination.exists():
        temp = STORE / (s['id'] + '.staging')
        require(not temp.exists(), 'Incomplete prior bootstrap; inspect it before retrying')
        shutil.copytree(source, temp, symlinks=False)
        # Source paths were checked for symlinks during prepare and are rechecked before execution.
        manifest(source)
        verify_payload(temp)
        for p in [temp] + list(temp.rglob('*')):
            os.chown(p, 0, 0)
            os.chmod(p, 0o700 if p.is_dir() else 0o600)
        os.rename(temp, destination)
    else:
        secure_root(destination)
        require(sha(destination / 'payload-sha256.json') == sha(source / 'payload-sha256.json'), 'Transaction ID already belongs to another payload')
    # A dedicated session contains every ordinary installer/networksetup child.
    # The recovery watcher runs in a DIFFERENT session and can stop this entire
    # group before restoring, even if the worker itself was killed.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    worker = subprocess.Popen([PYTHON, '-I', '-B', str(destination / 'engine/admin.py'), '_run', action, str(destination)],
                              start_new_session=True, stdin=subprocess.DEVNULL, env=SAFE_ENV)
    try:
        return worker.wait()
    except KeyboardInterrupt:
        worker.terminate()
        return worker.wait()


def group_members(group, exclude=None):
    found = []
    rows = run(['/bin/ps', '-axo', 'pid=,pgid=']).stdout.splitlines()
    for line in rows:
        values = line.split()
        if len(values) == 2 and values[0].isdigit() and values[1].isdigit():
            pid, pgid = map(int, values)
            if pgid == group and pid != exclude:
                try:
                    if os.getpgid(pid) == group:
                        found.append(pid)
                except ProcessLookupError:
                    pass
    return found


def terminate_group(group, exclude=None):
    require(group > 1 and (group != os.getpgrp() or exclude == os.getpid()), 'Refusing to terminate the recovery process group')
    for sig, budget in [(signal.SIGTERM, 3), (signal.SIGKILL, 3)]:
        for pid in group_members(group, exclude):
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, sig)
        deadline = time.monotonic() + budget
        while group_members(group, exclude) and time.monotonic() < deadline:
            time.sleep(.1)
        if not group_members(group, exclude):
            return
    require(not group_members(group, exclude), 'Transaction children did not stop; refusing a racing rollback')


def quiesce_children():
    require(os.getpgrp() == os.getpid(), 'Administrator worker must have an isolated process group')
    terminate_group(os.getpid(), exclude=os.getpid())


def check_live(s, bundle):
    for name, digest in read_json(bundle / 'expected-live.json').items():
        require(sha(Path(s['config_dir']) / name) == digest, 'Live configuration changed since prepare: ' + name)
    for p, digest in s['binary_hashes'].items():
        require(sha(p) == digest, 'Client binary changed since preparation')
    require(not GUARD.exists() and not LAUNCH.exists(), 'An existing guard appeared; refusing fresh installation')
    require(not run(['/sbin/ifconfig', s['device']], check=False).returncode == 0, 'Prepared TUN device is now occupied')


def install_service(s, bundle):
    if not s['needs_service']:
        require(SERVICE_PLIST.exists(), 'Original service disappeared')
        return
    require(not SERVICE_PLIST.exists(), 'Another service was installed after prepare')
    atomic(bundle / 'service-install-attempted', 'yes\n')
    run([s['installer'], '--install-service', '--install-core', s['core'], '--sha256', s['binary_hashes'][s['core']]],
        timeout=90, env=dict(SAFE_ENV, CLASH_VERGE_SERVICE_GID=str(s['gid'])))
    require(SERVICE_PLIST.exists(), 'Official service installation did not create its launch daemon')


def configure(s, bundle):
    log('Stopping GUI before editing settings')
    stop_gui(s)
    log('Checking/installing the hash-pinned official service')
    install_service(s, bundle)
    target = Path(s['config_dir'])
    if s.get('import_profile'):
        log('Importing verified VPS as a new local profile; preserving existing subscriptions')
        copy_user(bundle / 'stage/node-profile.yaml', target / s['subscription'], s)
        copy_user(bundle / 'stage/profiles.yaml', target / 'profiles.yaml', s)
    for src, dest in [('config.yaml', 'config.yaml'), ('verge.yaml', 'verge.yaml'), ('Script.js', s['script_file']), ('Merge.yaml', s['merge_file'])]:
        log('Installing prepared file: ' + dest)
        copy_user(bundle / 'stage' / src, target / dest, s)
    for src in (bundle / 'stage/ruleset').glob('*.yaml'):
        copy_user(src, target / 'ruleset' / src.name, s)
    copy_user(bundle / 'stage/geosite.dat', target / 'geosite.dat', s)
    log('Registering login launch agent and reopening GUI')
    install_login(s)
    open_gui(s)
    deadline = time.monotonic() + 80
    while time.monotonic() < deadline:
        try:
            actual_tun(s)
            break
        except Exception:
            time.sleep(1)
    else:
        # One bounded reload; no repeated reinstall/restart loop.
        api(s, '/configs?force=true', 'PUT', {'path': str(target / 'clash-verge.yaml')}, timeout=15)
        actual_tun(s)
    log('Verified TUN; applying system DNS/proxy settings')
    set_network(s)
    log('Waiting for ordinary-user Claude transport, maximum 120 seconds')
    health(s, 120)
    verify_subscription_files(s, bundle)
    log('Client/TUN/network deployed; original subscription hash unchanged')


def parent_hook(s):
    rules = run(['/sbin/pfctl', '-sr']).stdout
    require(not any(re.match(r'\s*(pass|anchor).*\bquick\b', line) for line in rules.splitlines()
                    if 'com.apple/*' not in line), 'Earlier/main quick rules need manual reachability review')
    if re.search(r'^anchor "com\.apple/\*"', rules, re.M):
        return
    require(s['options']['allow_default_pf_reload'], 'PF parent hook missing; default rules reload was not approved')
    require(not rules.strip(), 'PF parent hook missing from nonempty custom ruleset; not overwriting it')
    for arg in ['-sn', '-s queue']:
        require(not run(['/sbin/pfctl'] + arg.split()).stdout.strip(), 'Custom PF NAT/queue rules prevent default reload')
    for path, digest in s['pf_hashes'].items():
        secure_root(path)
        require(sha(path) == digest, 'Apple PF defaults changed since approval')
    run(['/sbin/pfctl', '-n', '-f', '/etc/pf.conf'])
    require(not run(['/sbin/pfctl', '-sr']).stdout.strip(), 'PF rules changed while checking')
    run(['/sbin/pfctl', '-f', '/etc/pf.conf'])
    require('anchor "com.apple/*"' in run(['/sbin/pfctl', '-sr']).stdout, 'PF parent hook not reachable')


def pf_enable():
    STATE.mkdir(mode=0o700, exist_ok=True)
    secure_root(STATE.resolve())
    token = STATE / 'pf-token'
    status = run(['/sbin/pfctl', '-si']).stdout
    if token.exists() and 'Status: Enabled' in status:
        return
    if token.exists():
        old = token.read_text().strip()
        if old.isdigit():
            run(['/sbin/pfctl', '-X', old], check=False)
    p = run(['/sbin/pfctl', '-E'])
    m = re.search(r'Token\s*:\s*(\d+)', p.stdout + p.stderr)
    require(m, 'PF did not return an enable token')
    atomic(token, m.group(1) + '\n')


def load_pf(s, tun):
    parent_hook(s)
    STATE.mkdir(mode=0o700, exist_ok=True)
    secure_root(STATE.resolve())
    raw = render_pf(tun, s['ports'])
    file = STATE / 'rules.pf'
    atomic(file, raw)
    run(['/sbin/pfctl', '-n', '-f', str(file)])
    run(['/sbin/pfctl', '-a', ANCHOR, '-f', str(file)])
    pf_enable()
    actual = run(['/sbin/pfctl', '-a', ANCHOR, '-sr']).stdout
    require('clash-guard:block' in actual, 'Guard rules not attached')
    atomic(STATE / 'expected-rules.txt', actual)


def clear_host_states():
    interface = ''
    addresses = set()
    for line in run(['/sbin/ifconfig', '-a']).stdout.splitlines():
        if line and not line[0].isspace():
            interface = line.split(':')[0]
        f = line.split()
        if len(f) > 1 and f[0] in ['inet', 'inet6']:
            try:
                addresses.add(str(ipaddress.ip_address(f[1].split('%')[0])))
            except ValueError:
                pass
    require(addresses, 'No host source addresses found for targeted stale-state cleanup')
    for addr in sorted(addresses):
        run(['/sbin/pfctl', '-k', addr])


def off(s, remove=False):
    if GUARD.exists():
        secure_root(GUARD)
        require(read_json(GUARD / 'settings.json')['id'] == s['id'], 'Refusing to remove another deployment')
        atomic(GUARD / 'disabled', 'disabled\n')
    run(['/bin/launchctl', 'bootout', 'system/' + LABEL], check=False)
    require(run(['/bin/launchctl', 'print', 'system/' + LABEL], check=False).returncode != 0, 'Guard service is still running')
    run(['/sbin/pfctl', '-a', ANCHOR, '-f', '/dev/null'])
    token = STATE / 'pf-token'
    if token.exists():
        value = token.read_text().strip()
        require(value.isdigit(), 'Invalid PF token')
        run(['/sbin/pfctl', '-X', value], check=False)
        token.unlink()
    if LAUNCH.exists():
        LAUNCH.unlink()
    if remove and GUARD.exists():
        shutil.rmtree(GUARD)


def write_guard(s, bundle):
    log('Verifying healthy TUN and PF parent hook before guard installation')
    require(not GUARD.exists() and not LAUNCH.exists(), 'Guard already installed')
    actual_tun(s)
    parent_hook(s)
    payload = bundle / 'guard-payload'
    payload.mkdir(mode=0o700)
    for src in (bundle / 'engine').glob('*.py'):
        atomic(payload / src.name, src.read_bytes())
    dump(payload / 'settings.json', s)
    dump(payload / 'network-baseline.json', read_json(bundle / 'original/network.json'))
    atomic(payload / 'off.sh', '#!/bin/sh\nPATH=/usr/bin:/bin:/usr/sbin:/sbin\nexport PATH\nunset PYTHONPATH PYTHONHOME ENV BASH_ENV\nexec /usr/bin/python3 -I -B "/Library/Application Support/clash-guard/admin.py" _off\n', mode=0o700)
    os.rename(payload, GUARD)
    plist = {'Label': LABEL, 'ProgramArguments': [PYTHON, '-I', '-B', str(GUARD / 'admin.py'), '_daemon'],
             'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 2,
             'StandardOutPath': str(GUARD / 'daemon.log'), 'StandardErrorPath': str(GUARD / 'daemon.log'),
             'EnvironmentVariables': SAFE_ENV, 'Umask': 0o077}
    atomic(LAUNCH, plistlib.dumps(plist), mode=0o644)
    run(['/usr/bin/plutil', '-lint', str(LAUNCH)])
    load_pf(s, actual_tun(s))
    log('Guard attached; clearing pre-existing host-source states with approved scope')
    clear_host_states()
    run(['/bin/launchctl', 'enable', 'system/' + LABEL])
    run(['/bin/launchctl', 'bootstrap', 'system', str(LAUNCH)])
    log('Guard service started; checking ordinary-user network and PF/launchd state')
    health(s, 120)
    check_guard(s)


def check_guard(s):
    parent_hook(s)
    require('clash-guard:block' in run(['/sbin/pfctl', '-a', ANCHOR, '-sr']).stdout, 'Guard PF rules missing')
    status = run(['/bin/launchctl', 'print', 'system/' + LABEL]).stdout
    require('state = running' in status, 'Guard launch daemon not running')
    require('Status: Enabled' in run(['/sbin/pfctl', '-si']).stdout, 'PF is disabled')
    require((GUARD / 'off.sh').is_file(), 'Offline off command missing')


def intent(s):
    path = Path(s['config_dir']) / 'verge.yaml'
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == s['uid'] and not st.st_mode & 0o022, 'Untrusted preference file')
    value = yaml_read(path)
    flags = value.get('enable_tun_mode'), value.get('enable_system_proxy')
    require(all(type(v) is bool for v in flags), 'Unknown intent schema')
    return flags


def daemon_decision(s):
    if (GUARD / 'hold-restricted').exists():
        return 'restricted'
    gui = bool(gui_processes(s))
    t, p, actual, valid = None, None, None, False
    try:
        t, p = intent(s)
        root_core(s)
        state = api(s, '/configs')
        current_ports = [state.get(k) for k in ['mixed-port', 'port', 'socks-port', 'redir-port']]
        known = set(s['ports'])
        known.update(p for p in current_ports if type(p) is int and 0 < p < 65536)
        cache = STATE / 'ports.json'
        if cache.exists():
            secure_root(cache.resolve())
            cached = read_json(cache)
            if cached.get('id') == s['id']:
                require(all(type(v) is int and 0 < v < 65536 for v in cached.get('ports', [])), 'Invalid port cache')
                known.update(cached['ports'])
        s['ports'] = sorted(known)
        dump(cache, {'id': s['id'], 'ports': s['ports']})
        actual = state.get('tun', {}).get('enable')
        if actual is True:
            actual_tun(s)
        valid = type(actual) is bool
    except Exception:
        pass
    return switch_decision(gui, t, p, actual, valid, s['options']['native_on_both_off'], s['options']['native_on_gui_exit'])


def daemon():
    secure_root(GUARD)
    for name in ['admin.py', 'guardlib.py', 'macos.py', 'settings.json']:
        secure_root(GUARD / name)
    s = read_json(GUARD / 'settings.json')
    baseline = read_json(GUARD / 'network-baseline.json')
    last = ''
    while not (GUARD / 'disabled').exists():
        try:
            mode = daemon_decision(s)
            if mode == 'native':
                # Recheck intent before each operation. Never use node health as release intent.
                require(daemon_decision(s) == 'native', 'Intent changed')
                if not gui_processes(s):
                    if any(p['uid'] == 0 and p['path'] in s['core_paths'] for p in processes()):
                        root_core(s)
                        api(s, '/configs', 'PATCH', {'tun': {'enable': False}})
                        require(api(s, '/configs').get('tun', {}).get('enable') is False, 'Persistent service TUN did not stop')
                require(daemon_decision(s) == 'native', 'Intent changed before cleanup')
                clear_owned_network(s, baseline)
                require(daemon_decision(s) == 'native', 'Intent changed before release')
                run(['/sbin/pfctl', '-a', ANCHOR, '-f', '/dev/null'])
            else:
                # The original no-state permissions cannot survive a TUN/intent transition.
                tun = s['device'] if mode == 'guarding' else ''
                actual = run(['/sbin/pfctl', '-a', ANCHOR, '-sr'], check=False).stdout
                expected = (STATE / 'expected-rules.txt').read_text() if (STATE / 'expected-rules.txt').exists() else ''
                source = (STATE / 'rules.pf').read_text() if (STATE / 'rules.pf').exists() else ''
                if last != mode or actual != expected or source != render_pf(tun, s['ports']):
                    load_pf(s, tun)
                else:
                    parent_hook(s)
                    pf_enable()
                if mode == 'guarding' and last != mode:
                    set_network(s, system_proxy=intent(s)[1])
            dump(GUARD / 'status.json', {'mode': mode, 'time': time.time(), 'id': s['id']})
            if mode != last:
                log('guard mode=' + mode)
            last = mode
        except Exception as e:
            # Do not clear PF on exception, daemon death or a node outage.
            dump(GUARD / 'status.json', {'mode': 'error', 'error': str(e), 'time': time.time()})
            if last != 'error':
                log('guard error: ' + str(e))
            last = 'error'
        time.sleep(1)


def recover(s, snapshot, bundle, original=False):
    # Ownership is a precondition, not a recoverable step. A stale backup must
    # never continue by replacing a newer deployment's client or system DNS.
    if GUARD.exists():
        secure_root(GUARD)
        require(read_json(GUARD / 'settings.json')['id'] == s['id'], 'Another deployment owns the guard; no recovery changes made')
    state = read_json(snapshot / 'state.json')
    preserved_guard = not original and (snapshot / 'guard-present').exists()
    def pause_guard():
        if preserved_guard:
            secure_root(GUARD)
            require(read_json(GUARD / 'settings.json')['id'] == s['id'], 'Guard owner changed')
            atomic(GUARD / 'hold-restricted', 'Recovery in progress or TUN unavailable\n')
            atomic(GUARD / 'disabled', 'Temporarily stopping supervisor, PF retained\n')
            run(['/bin/launchctl', 'bootout', 'system/' + LABEL], check=False)
            require(run(['/bin/launchctl', 'print', 'system/' + LABEL], check=False).returncode != 0, 'Supervisor did not stop')
            load_pf(s, '')
        elif GUARD.exists():
            off(s, remove=True)
    def restart_guard():
        if preserved_guard:
            atomic(LAUNCH, (snapshot / 'guard.plist').read_bytes(), mode=0o644)
            if (GUARD / 'disabled').exists():
                (GUARD / 'disabled').unlink()
            # The hold marker makes the daemon start restricted, independent of
            # GUI presence, native-mode preferences, node health or TUN success.
            run(['/bin/launchctl', 'enable', 'system/' + LABEL])
            run(['/bin/launchctl', 'bootstrap', 'system', str(LAUNCH)])
    def release_to_healthy_tun():
        if preserved_guard:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                try:
                    tun = actual_tun(s)
                    load_pf(s, tun)
                    (GUARD / 'hold-restricted').unlink(missing_ok=True)
                    return
                except Exception:
                    time.sleep(1)
            raise GuardError('TUN unavailable after recovery; restricted guard remains active')
    def stop_tun():
        with contextlib.suppress(Exception):
            api(s, '/configs', 'PATCH', {'tun': {'enable': False}})
    def uninstall_new_service():
        if original and s['needs_service'] and (bundle / 'service-install-attempted').exists():
            require(sha(s['uninstaller']) == s['binary_hashes'][s['uninstaller']], 'Official uninstaller changed')
            run([s['uninstaller']], timeout=90)
            # Never sweep /tmp/verge; only remove stale entries owned by this client after all its cores have stopped.
    def reopen():
        def restored_health():
            if original and s.get('import_profile'):
                result = baseline_health(s)
                log('Original baseline recovery: ' + json.dumps(result))
            else:
                health(s, 120, needs_tun=not original)
        if state['gui_running']:
            open_gui(s)
            try:
                release_to_healthy_tun()
                restored_health()
            except Exception:
                if preserved_guard:
                    atomic(GUARD / 'hold-restricted', 'Retrying client recovery\n')
                    load_pf(s, '')
                stop_gui(s)
                # Retry only when the configured port is free or is owned by the known core.
                owners = run(['/usr/sbin/lsof', '-nP', '-iTCP:' + str(s['mixed_port']), '-sTCP:LISTEN', '-Fp'], check=False).stdout
                known = {p['pid'] for p in processes() if p['path'] in s['core_paths'] + [s['core']]}
                pids = {int(x[1:]) for x in owners.splitlines() if re.fullmatch(r'p\d+', x)}
                require(pids <= known, 'Proxy port is owned by another program; not killing it')
                open_gui(s)
                release_to_healthy_tun()
                restored_health()
    steps = [('preserve restricted guard or remove new-only guard', pause_guard),
             ('stop GUI', lambda: stop_gui(s)), ('disable TUN', stop_tun),
             ('restore client configuration', lambda: restore_config(snapshot, s)),
             ('remove newly installed official service', uninstall_new_service),
             ('restore guard supervisor before testing TUN', restart_guard),
             ('restore DNS and system proxies', lambda: restore_network(read_json(snapshot / 'network.json'), log)),
             ('reopen original client and verify port/transport', reopen),
             ('restore exact network baseline after client startup', lambda: restore_network(read_json(snapshot / 'network.json'), log))]
    errors = restore_steps(steps, log)
    if preserved_guard:
        try:
            check_guard(s)
        except Exception as e:
            errors.append('restore guard: ' + str(e))
    return errors


def watchdog(bundle, pid, phase, timeout, start_token=None):
    global LOG
    LOG = bundle / 'watchdog.log'
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    deadline = time.monotonic() + timeout
    done = bundle / ('done-' + phase)
    while not done.exists():
        try:
            os.kill(pid, 0)
            alive = start_token is None or run(['/bin/ps', '-p', str(pid), '-o', 'lstart='], check=False).stdout.strip() == start_token
        except ProcessLookupError:
            alive = False
        if not alive or time.monotonic() >= deadline:
            # Stop mutating children as well as their parent before taking the
            # recovery lock. No late installer may overwrite restored state.
            terminate_group(pid)
            # Parent releases the advisory lock on death; serialize recovery.
            with open(STORE / 'deployment.lock', 'a') as global_lock, open(bundle / 'transaction.lock', 'a') as lock:
                fcntl.flock(global_lock, fcntl.LOCK_EX)
                fcntl.flock(lock, fcntl.LOCK_EX)
                if done.exists():
                    return
                s = read_json(bundle / 'settings.json')
                snapshot = bundle / ('original' if phase == 'apply' else 'checkpoint-' + phase)
                errors = recover(s, snapshot, bundle, original=phase == 'apply')
                dump(done, {'status': 'watchdog_rollback', 'errors': errors})
                export_reports(bundle, s)
            return
        time.sleep(1)


def export_reports(bundle, s):
    destination = Path(s['backup']) / 'results'
    destination.mkdir(mode=0o700, exist_ok=True)
    require(not destination.is_symlink(), 'Unsafe results directory')
    os.chown(destination, s['uid'], s['gid'])
    for p in bundle.iterdir():
        if p.is_file() and (p.name.endswith(('.log', '.report.json', '.jsonl')) or p.name.startswith('done-')):
            atomic(destination / p.name, p.read_bytes(), owner=(s['uid'], s['gid']))
    if (GUARD / 'status.json').exists():
        atomic(destination / 'guard-status.json', (GUARD / 'status.json').read_bytes(), owner=(s['uid'], s['gid']))


def execute(phase, bundle):
    global LOG
    secure_root(bundle)
    verify_payload(bundle)
    require(os.getpgrp() == os.getpid(), 'Worker was not started in its dedicated session')
    s = read_json(bundle / 'settings.json')
    LOG = bundle / (phase + '.log')
    done = bundle / ('done-' + phase)
    require(phase == 'restore' or not done.exists(), 'This phase already ran. Read its report; do not repeat it unchanged.')
    with open(STORE / 'deployment.lock', 'a') as global_lock, open(bundle / 'transaction.lock', 'a') as lock:
        fcntl.flock(global_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        inflight = STORE / 'inflight.json'
        previous = read_json(inflight) if inflight.exists() else None
        unfinished = previous and not (STORE / previous['id'] / ('done-' + previous['phase'])).exists()
        require(not unfinished or (phase == 'restore' and previous['id'] == s['id']), 'Another transaction has not finished recovery; inspect it before deploying')
        if phase == 'restore':
            require(not previous or previous['id'] == s['id'], 'A newer desktop transaction owns this installation; use its restore first')
            if unfinished:
                terminate_group(previous['pid'])
            errors = recover(s, bundle / 'original', bundle, original=True)
            dump(done, {'status': 'restored' if not errors else 'recovery_incomplete', 'errors': errors})
            if unfinished:
                dump(bundle / ('done-' + previous['phase']), {'status': 'manual_restore', 'errors': errors})
            export_reports(bundle, s)
            require(not errors, 'Some recovery steps failed; see restore.log')
            return
        if phase == 'apply':
            check_live(s, bundle)
            snapshot = bundle / 'original'
        else:
            require(read_json(bundle / 'done-apply')['status'] == 'committed', 'Network phase not committed')
            if phase == 'guard':
                report = read_json(bundle / 'network.report.json')
                require(report['gate_passed'], 'Acceptance 1–6 has unresolved failures')
                from accept import runtime_checks
                runtime_checks(s, bundle)
                health(s, 120)
                exit_probe = curl_probe(s, 'https://ipinfo.io/json')
                dump(bundle / 'guard-exit.report.json', exit_probe)
                require(exit_probe['ip'] == s['options']['expected_exit_ip'] and exit_probe['country'] == s['options']['expected_exit_country'], 'Exit identity changed before firewall installation')
            else:
                check_guard(s)
            snapshot = bundle / ('checkpoint-' + phase)
            snapshot_to(snapshot, s)
            if GUARD.exists() and LAUNCH.exists():
                atomic(snapshot / 'guard-present', 'yes\n')
                shutil.copyfile(LAUNCH, snapshot / 'guard.plist')
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        def abort(sig, frame):
            raise GuardError('Transaction interrupted by signal %s' % sig)
        signal.signal(signal.SIGTERM, abort)
        signal.signal(signal.SIGINT, abort)
        start_token = run(['/bin/ps', '-p', str(os.getpid()), '-o', 'lstart=']).stdout.strip()
        dump(inflight, {'id': s['id'], 'phase': phase, 'pid': os.getpid(), 'start': start_token})
        subprocess.Popen([PYTHON, '-I', '-B', str(bundle / 'engine/admin.py'), '_watch', str(bundle), str(os.getpid()), phase, '1200', start_token],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True, close_fds=True, env=SAFE_ENV)
        try:
            log('phase=' + phase + ' started; independent recovery supervisor armed')
            if phase == 'apply':
                configure(s, bundle)
                from accept import network_acceptance
                report = network_acceptance(s, bundle)
                dump(bundle / 'network.report.json', report)
                require(report['gate_passed'], 'Network acceptance did not pass; restoring original state')
            elif phase == 'guard':
                write_guard(s, bundle)
                dump(bundle / 'guard.report.json', {'items': {'7': {'status': 'pass', 'errors': 0},
                     '8': {'status': 'pass', 'boot_test': 'not_tested', 'self_heal_test': 'not_tested'}}})
            elif phase == 'drill':
                from accept import drills
                report = drills(s, bundle)
                dump(bundle / 'drill.report.json', report)
                require(report['passed'], 'A drill failed; returning to its healthy checkpoint')
            else:
                raise GuardError('Unknown phase')
            dump(done, {'status': 'committed', 'time': time.time()})
            log('phase committed')
        except BaseException as e:
            log('phase failed: ' + str(e))
            quiesce_children()
            errors = recover(s, snapshot, bundle, original=phase == 'apply')
            dump(done, {'status': 'rolled_back' if not errors else 'recovery_incomplete', 'failure': str(e), 'errors': errors})
            log('rollback finished; errors=' + str(len(errors)))
            raise
        finally:
            export_reports(bundle, s)


if __name__ == '__main__':
    import pwd
    try:
        require(os.geteuid() == 0, 'Run the generated shell entrypoint with sudo in Terminal')
        action = sys.argv[1]
        if action == '_run':
            execute(sys.argv[2], Path(sys.argv[3]))
        elif action == '_watch':
            watchdog(Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4], int(sys.argv[5]), sys.argv[6])
        elif action == '_daemon':
            daemon()
        elif action == '_off':
            secure_root(GUARD)
            off(read_json(GUARD / 'settings.json'))
            print('已解除本工具的断网防护；其他防火墙规则未清除。')
        elif action in ['apply', 'guard', 'drill', 'restore']:
            require(bootstrap(action, Path(sys.argv[2])) == 0, 'Administrator phase failed; read results before retrying')
        else:
            raise GuardError('Unknown action')
    except BaseException as e:
        print('FAILED: ' + str(e) + '\n请勿重复运行；回到原对话读取本批 results 日志。', file=sys.stderr)
        sys.exit(1)
