"""Instrumentation Linux du futur pilote L4 ; jamais exécutée à l'import.

Le fils attend une porte avant exec, pour permettre une observation procfs
indépendante du reçu de lancement. Aucun ptrace, mot de passe ou sudo de test.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import threading
import time

COMMAND = ['sudo', '-n', '--', '/usr/bin/true']


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def parse_stat(raw):
    left, sep, tail = str(raw).rpartition(') ')
    if not sep or '(' not in left:
        raise ValueError('invalid proc stat')
    pid, comm = left.split(' (', 1)
    fields = tail.split()
    if len(fields) < 20:
        raise ValueError('short proc stat')
    result = {'pid': int(pid), 'comm': comm, 'state': fields[0],
              'ppid': int(fields[1]), 'start_ticks': int(fields[19])}
    if result['pid'] <= 0 or result['start_ticks'] <= 0:
        raise ValueError('invalid process identity')
    return result


def read_identity(pid, proc_root='/proc'):
    root = Path(proc_root); path = root / str(int(pid))
    raw = (path / 'stat').read_text()
    first = parse_stat(raw)
    login = (path / 'loginuid').read_text().strip()
    session = (path / 'sessionid').read_text().strip()
    second = parse_stat((path / 'stat').read_text())
    if any(first[k] != second[k] for k in ('pid', 'ppid', 'start_ticks')):
        raise ValueError('process identity changed during observation')
    return {**first, 'login_uid': int(login), 'audit_session': int(session),
            'boot_id': (root / 'sys/kernel/random/boot_id').read_text().strip(),
            'observed_at_utc': utc(), 'stat_raw': raw,
            'stat_sha256': hashlib.sha256(raw.encode()).hexdigest()}


def capture_lineage(child_pid, parent_pid, proc_root='/proc'):
    child = read_identity(child_pid, proc_root)
    parent = read_identity(parent_pid, proc_root)
    ancestor = read_identity(parent['ppid'], proc_root)
    if child['ppid'] != parent['pid'] or ancestor['comm'] != 'sshd':
        raise ValueError('direct SSH lineage not demonstrated')
    if len({x['boot_id'] for x in (child, parent, ancestor)}) != 1:
        raise ValueError('mixed boot identities')
    if child['audit_session'] in (-1, 4294967295) or child['login_uid'] in (-1, 4294967295):
        raise ValueError('audit identity unavailable')
    if any(x['audit_session'] != child['audit_session'] or x['login_uid'] != child['login_uid']
           for x in (parent, ancestor)):
        raise ValueError('inconsistent audit lineage')
    return {**child, 'parent_start_ticks': parent['start_ticks'],
            'parent_ppid': parent['ppid'], 'parent_stat_raw': parent['stat_raw'],
            'sshd_stat_raw': ancestor['stat_raw'],
            'observation_source': 'kernel-procfs-before-exec-gate'}


def preflight():
    """Lecture seulement : aucune création de fils ni invocation sudo."""
    own = read_identity(os.getpid())
    parent = read_identity(own['ppid'])
    return {'boot_id': own['boot_id'], 'hostname': socket.gethostname(),
            'uid': os.getuid(), 'parent_comm': parent['comm'],
            'audit_session': own['audit_session'], 'login_uid': own['login_uid'],
            'parent_audit_session': parent['audit_session'], 'parent_login_uid': parent['login_uid'],
            'sudo_binary_available': Path('/usr/bin/sudo').is_file(),
            'fork_available': hasattr(os, 'fork'), 'procfs_readable': True,
            'sudo_invocations': 0}


def _wait(pid, seconds):
    until = time.monotonic() + seconds
    while True:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            return status
        if time.monotonic() >= until:
            return None
        time.sleep(.01)


def _cleanup(pid, identity, proc_root='/proc'):
    """Ne signale que l'identité capturée ; un refus reste non confirmé."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        status = _wait(pid, .01)
        if status is not None:
            return {'confirmed_stopped': True, 'wait_status': status, 'scope': 'watched-child'}
        try:
            current = parse_stat((Path(proc_root) / str(pid) / 'stat').read_text())
            if current['start_ticks'] != identity['start_ticks']:
                return {'confirmed_stopped': False, 'error': 'identity-mismatch-no-signal'}
            os.kill(pid, sig)
        except (PermissionError, FileNotFoundError, ProcessLookupError, ValueError) as exc:
            status = _wait(pid, .01)
            return {'confirmed_stopped': status is not None, 'wait_status': status,
                    'error': type(exc).__name__, 'scope': 'watched-child'}
        status = _wait(pid, .3)
        if status is not None:
            return {'confirmed_stopped': True, 'wait_status': status, 'scope': 'watched-child'}
    return {'confirmed_stopped': False, 'error': 'bounded-cleanup-unresolved', 'scope': 'watched-child'}


def run_probe():
    """À appeler uniquement par le runner L4 après autorisation explicite."""
    if not hasattr(os, 'fork') or not Path('/usr/bin/sudo').is_file():
        raise RuntimeError('Linux fork and /usr/bin/sudo required')
    started = utc(); parent_pid = os.getpid()
    gate_r, gate_w = os.pipe(); out_r, out_w = os.pipe(); err_r, err_w = os.pipe()
    exec_r, exec_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            for fd in (gate_w, out_r, err_r, exec_r): os.close(fd)
            if os.read(gate_r, 1) != b'G': os._exit(125)
            os.close(gate_r)
            null = os.open(os.devnull, os.O_RDONLY); os.dup2(null, 0); os.close(null)
            os.dup2(out_w, 1); os.dup2(err_w, 2)
            os.close(out_w); os.close(err_w)
            os.execv('/usr/bin/sudo', COMMAND)
        except BaseException as exc:
            try: os.write(exec_w, type(exc).__name__.encode())
            finally: os._exit(127)
    for fd in (gate_r, out_w, err_w, exec_w): os.close(fd)
    result = {'started_at_utc': started, 'target_process_pid': parent_pid,
              'hostname': socket.gethostname(), 'ssh_connection': os.environ.get('SSH_CONNECTION'),
              'command_argv': COMMAND, 'command_sha256': hashlib.sha256(json.dumps(COMMAND, separators=(',', ':')).encode()).hexdigest(),
              'sudo_pid': pid, 'invocations_attempted': 0, 'process_observations': [],
              'capture_complete': False}
    identity = None
    try:
        box = {}
        def observe():
            try: box['observation'] = capture_lineage(pid, parent_pid)
            except Exception as exc: box['error'] = type(exc).__name__ + ':' + str(exc)
        observer = threading.Thread(target=observe, daemon=True); observer.start(); observer.join(.5)
        if observer.is_alive() or 'observation' not in box:
            result['capture_error'] = box.get('error', 'procfs-observation-timeout')
            os.close(gate_w); gate_w = None
            status = _wait(pid, .5)
            result['cleanup'] = {'confirmed_stopped': status is not None, 'scope': 'pre-exec-child'}
            return result
        identity = box['observation']; result['process_observations'] = [identity]
        chunks = {'stdout': bytearray(), 'stderr': bytearray()}; truncated = []
        def drain(fd, name):
            with os.fdopen(fd, 'rb') as stream:
                for data in iter(lambda: stream.read(4096), b''):
                    room = max(0, 65536 - len(chunks[name])); chunks[name].extend(data[:room])
                    if len(data) > room: truncated.append(name)
        threads = [threading.Thread(target=drain, args=(fd, name), daemon=True)
                   for fd, name in ((out_r, 'stdout'), (err_r, 'stderr'))]
        for thread in threads: thread.start()
        os.write(gate_w, b'G'); os.close(gate_w); gate_w = None
        result['invocations_attempted'] = 1
        status = _wait(pid, 4.)
        if status is None:
            result['cleanup'] = _cleanup(pid, identity); result['execution_error'] = 'target-deadline-exceeded'
        else:
            result['sudo_exit_code'] = os.waitstatus_to_exitcode(status)
            result['cleanup'] = {'confirmed_stopped': True, 'scope': 'watched-child'}
        for thread in threads: thread.join(.5)
        if not result['cleanup']['confirmed_stopped']:
            result['capture_error'] = 'remote-process-cleanup-unconfirmed'
            return result
        exec_error = os.read(exec_r, 4096)
        result['exec_confirmed'] = not exec_error
        if exec_error: result['execution_error'] = exec_error.decode(errors='replace')
        result['output_truncated'] = bool(truncated)
        for name, data in chunks.items():
            result[name + '_base64'] = base64.b64encode(data).decode()
            result[name + '_sha256'] = hashlib.sha256(data).hexdigest()
        result['capture_complete'] = not result.get('execution_error') and not truncated and all(not t.is_alive() for t in threads)
        return result
    except Exception as exc:
        result['capture_error'] = type(exc).__name__
        if identity is not None: result['cleanup'] = _cleanup(pid, identity)
        else:
            if gate_w is not None: os.close(gate_w); gate_w = None
            result['cleanup'] = {'confirmed_stopped': _wait(pid, .5) is not None, 'scope': 'pre-exec-child'}
        return result
    finally:
        if gate_w is not None: os.close(gate_w)
        for fd in (exec_r,):
            try: os.close(fd)
            except OSError: pass
        result['ended_at_utc'] = utc()
        result['training_ready'] = False


if __name__ == '__main__':
    print(json.dumps(run_probe()))
