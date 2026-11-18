"""Association sudo hors ligne, stricte et séparée des caractéristiques ML.

Aucune commande distante, aucune création automatique d'annotation persistante.
Journald et sa copie Wazuh sont une seule source. Le reçu et les observations
de processus/socket doivent provenir de la future instrumentation indépendante.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .boot_id import canonical_boot_id
from .io_utils import load_json, sha256_file, write_new_json
from .marker_normalization import normalize_instrumentation_markers

COMMAND = ['sudo', '-n', '--', '/usr/bin/true']
COMMAND_SHA256 = hashlib.sha256(json.dumps(COMMAND, separators=(',', ':')).encode()).hexdigest()
PREFIX = re.compile(r'^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+\S+\s+)?sudo\[(\d+)\]:\s*(.*)$', re.S)


def _utc(value):
    stamp = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if stamp.tzinfo is None or stamp.utcoffset() != timezone.utc.utcoffset(stamp):
        raise ValueError('UTC requis')
    return stamp.timestamp()


def _pid_message(alert):
    line = str(alert.get('full_log') or '')
    match = PREFIX.fullmatch(line)
    data = alert.get('data') or {}
    explicit = {int(data[k]) for k in ('pid', 'processid') if data.get(k) is not None}
    if match:
        explicit.add(int(match[1]))
    if len(explicit) != 1:
        return None, None
    return next(iter(explicit)), match[2] if match else line


def associate_sudo_event(alert, journal, receipts, process_observations, socket_observations):
    """Retourne uniquement une décision sidecar ; absence de preuve => excluded.

    Une observation processus requiert PID/start_ticks et la filiation jusqu'au
    processus de session, avec BootId. Un PID ou une commande seuls ne suffisent
    jamais. Les doublons de curseurs et reçus concurrents ambigus sont refusés.
    """
    excluded = lambda reason: {'decision': 'excluded', 'activity_id': None, 'reason': reason}
    try:
        pid, message = _pid_message(alert)
        if not pid:
            return excluded('wazuh-sudo-pid-missing-or-conflicting')
        cursors = [str(j['__CURSOR']) for j in journal]
        if len(cursors) != len(set(cursors)):
            return excluded('duplicate-journal-cursor')
        matches = []
        for receipt in receipts:
            if receipt['command_argv'] != COMMAND or receipt['command_sha256'] != COMMAND_SHA256:
                continue
            boot = canonical_boot_id(receipt['boot_id'])
            if receipt['sudo_pid'] != pid or receipt['agent_name'] != alert['agent']['name']:
                continue
            if not (_utc(receipt['collection_started_at_utc']) <= _utc(alert['timestamp'])
                    <= _utc(receipt['collection_ended_at_utc'])):
                continue
            observed = [p for p in process_observations if p['pid'] == pid
                and canonical_boot_id(p['boot_id']) == boot
                and p['start_ticks'] == receipt['sudo_start_ticks']
                and p['ppid'] == receipt['target_process_pid']
                and p['parent_start_ticks'] == receipt['target_process_start_ticks']
                and p['parent_ppid'] == receipt['sshd_pid']]
            if len(observed) != 1:
                continue
            connection = receipt['controller_socket']
            fields = ('source_ip', 'source_port', 'target_ip', 'target_port')
            if any(connection[k] != receipt['target_ssh_connection'][k] for k in fields):
                continue
            sockets = {tuple(s[k] for k in fields) for s in socket_observations
                if s['pid'] == receipt['ssh_client_pid'] and s.get('status') == 'ESTABLISHED'}
            if sockets != {tuple(connection[k] for k in fields)}:
                continue
            rows = [j for j in journal if int(j['_PID']) == pid
                and canonical_boot_id(j['_BOOT_ID']) == boot
                and j.get('_COMM') == 'sudo'
                and j.get('_HOSTNAME') == receipt['hostname']
                and str(j.get('_AUDIT_LOGINUID')) == str(receipt['login_uid'])
                and str(j.get('_AUDIT_SESSION')) == str(receipt['audit_session'])]
            if str(receipt['audit_session']) in ('', '4294967295'):
                continue
            source = [j for j in rows if j['MESSAGE'] == message]
            command_rows = [j for j in rows if str(j['MESSAGE']).rsplit('COMMAND=', 1)[-1] == '/usr/bin/true'
                and 'COMMAND=' in str(j['MESSAGE'])]
            if len(source) != 1 or not command_rows:
                continue
            stamp = int(source[0]['__REALTIME_TIMESTAMP']) / 1_000_000
            if not _utc(receipt['started_at_utc']) <= stamp <= _utc(receipt['ended_at_utc']):
                continue
            if not (_utc(receipt['started_at_utc']) <= _utc(observed[0]['observed_at_utc'])
                    <= _utc(receipt['ended_at_utc'])):
                continue
            matches.append((receipt['activity_id'], source[0]['__CURSOR']))
        if len(matches) != 1:
            return excluded('no-exclusive-sudo-process-session-command-chain' if not matches else 'multiple-receipt-identities')
        return {'decision': 'member-verified', 'confidence': 'verified',
                'activity_id': matches[0][0], 'journal_cursor': matches[0][1],
                'reason': 'independent-process-and-socket-observations+exact-journal-wazuh-source',
                'features_updated': False}
    except (KeyError, TypeError, ValueError, OverflowError):
        return excluded('incomplete-or-malformed-proof-bundle')


def observable_projection(alert, markers=()):
    """Projection de diagnostic, non branchée sur le modèle ou ses features V1."""
    data = alert.get('data') or {}
    values = {'rule_id': str((alert.get('rule') or {}).get('id') or ''),
              'description': str((alert.get('rule') or {}).get('description') or ''),
              'agent_name': str((alert.get('agent') or {}).get('name') or ''),
              'source_user': str(data.get('srcuser') or ''),
              'target_user': str(data.get('dstuser') or '')}
    return {k: normalize_instrumentation_markers(v, markers) for k, v in values.items()}


def review_bundle(bundle_dir, output):
    """Vérifie les empreintes d'un bundle local avant toute décision sidecar.

    Le futur collecteur devra prouver l'origine effective de ces cinq sources.
    Leur déclaration dans un manifeste ne prouve pas à elle seule l'indépendance.
    """
    root = Path(bundle_dir).resolve()
    manifest = load_json(root / 'sudo-proof-bundle.json')
    if manifest.get('schema_version') != 'alertgraph-sudo-proof-bundle/1.0-experimental':
        raise ValueError('version du bundle inconnue')
    required = {'wazuh-events', 'journal-events', 'execution-receipts',
                'process-observations', 'socket-observations'}
    entries = manifest['files']
    if len(entries) != len(required) or {e['role'] for e in entries} != required:
        raise ValueError('cinq sources distinctes requises')
    rows = {}; paths = set()
    for entry in entries:
        path = (root / entry['path']).resolve()
        if not path.is_relative_to(root) or path in paths:
            raise ValueError('chemin de preuve hors bundle ou reutilise')
        paths.add(path)
        if sha256_file(path) != entry['sha256']:
            raise ValueError('preuve alteree: ' + entry['role'])
        rows[entry['role']] = [json.loads(line) for line in path.read_bytes().splitlines() if line]
    events = rows['wazuh-events']
    if len({e['id'] for e in events}) != len(events):
        raise ValueError('identifiants Wazuh dupliques')
    decisions = [{'wazuh_alert_id': e['id'], **associate_sudo_event(e,
        rows['journal-events'], rows['execution-receipts'], rows['process-observations'],
        rows['socket-observations'])} for e in events]
    report = {'bundle_manifest_sha256': sha256_file(root / 'sudo-proof-bundle.json'),
              'event_decisions': decisions, 'weak_labels_used': False,
              'ml_features_modified': False, 'execution_authorized': False, 'training_ready': False}
    write_new_json(Path(output), report)
    return report
