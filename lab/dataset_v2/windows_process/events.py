"""Association stricte XML Sysmon / Wazuh / observations noyau independantes."""
from __future__ import annotations

import calendar
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import uuid
import xml.etree.ElementTree as ET

from ..io_utils import load_json, sha256_file

PROVIDER = 'Microsoft-Windows-Sysmon'
PROVIDER_GUID = '5770385f-c22a-43e0-bf4c-06f5698ffbd9'
CHANNEL = 'Microsoft-Windows-Sysmon/Operational'
NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
FIELDS = ('UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'CommandLine',
          'User', 'ParentProcessGuid', 'ParentProcessId', 'ParentImage')


def guid(value):
    return str(uuid.UUID(str(value).strip('{}')))


def filetime(value):
    """Precision 100 ns preservee ; pas de float ni tolerance temporelle."""
    match = re.fullmatch(r'(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(?:\.(\d{1,7}))?(?:Z|\+00:00)?', str(value))
    if not match:
        raise ValueError('UTC Sysmon/FileTime invalide')
    dt = datetime.strptime(match[1] + ' ' + match[2], '%Y-%m-%d %H:%M:%S')
    return (calendar.timegm(dt.timetuple()) + 11644473600) * 10_000_000 + int((match[3] or '').ljust(7, '0'))


def parse_xml(raw):
    if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        raise ValueError('DTD/entites interdites')
    root = ET.fromstring(raw)
    system = root.find('e:System', NS)
    if system is None:
        raise ValueError('System absent')
    provider = system.find('e:Provider', NS)
    result = {'provider': provider.attrib['Name'], 'provider_guid': guid(provider.attrib['Guid']),
        'event_id': int(system.find('e:EventID', NS).text),
        'record_id': str(system.find('e:EventRecordID', NS).text),
        'computer': system.find('e:Computer', NS).text,
        'channel': system.find('e:Channel', NS).text,
        'system_time': system.find('e:TimeCreated', NS).attrib['SystemTime'], 'data': {}}
    for node in root.findall('e:EventData/e:Data', NS):
        name = node.attrib['Name']
        if name in result['data']:
            raise ValueError('champ XML duplique')
        result['data'][name] = node.text or ''
    if result['provider'] != PROVIDER or result['provider_guid'] != PROVIDER_GUID or result['channel'] != CHANNEL:
        raise ValueError('producteur/canal incorrect')
    return result


def event_key(source):
    return (source['provider_guid'], source['computer'].casefold(), source['channel'],
            source['record_id'], source['event_id'], source['system_time'])


def wazuh_matches(alert, source, profile):
    """Profil fixe de decodeur : aucun choix favorable champ par champ."""
    win = alert['data']['win']; system = win['system']; data = win['eventdata']
    key = (guid(system['providerGuid']), str(system['computer']).casefold(), system['channel'],
           str(system['eventRecordID']), int(system['eventID']), system['systemTime'])
    if key != event_key(source) or system['providerName'] != PROVIDER:
        return False
    if profile not in ('json-string-content', 'identity'):
        raise ValueError('profil de serialisation inconnu')
    for name in FIELDS:
        original = source['data'][name]
        expected = json.dumps(original, ensure_ascii=False)[1:-1] if profile == 'json-string-content' else original
        if data.get(name[0].lower() + name[1:]) != expected:
            return False
    return True


def associate(alert, sources, receipt, observations, *, agent, profile='json-string-content'):
    excluded = lambda why: {'decision': 'excluded', 'activity_id': None, 'reason': why}
    try:
        if (receipt['status'] != 'completed' or not receipt['cleanup']['confirmed_stopped']
                or not receipt['gate']['independent_identity_checked_before_release']
                or receipt['parent']['exit_code'] != 0 or receipt['child']['exit_code'] != 0):
            return excluded('execution-gate-or-cleanup-unconfirmed')
        if alert['agent']['name'] != agent or str(alert['data']['win']['system']['eventID']) != '1':
            return excluded('outside-agent-or-process-create-scope')
        if len({event_key(s) for s in sources}) != len(sources):
            return excluded('duplicate-source-event-identity')
        identities = {}; anchors = {}
        for role in ('parent', 'child'):
            witness = receipt[role]
            measured = [o for o in observations if o['role'] == role]
            if len(measured) != 1:
                return excluded('missing-or-ambiguous-independent-observation')
            observed = measured[0]
            if (observed['pid'] != witness['pid']
                    or observed['creation_filetime'] != witness['creation_filetime']
                    or observed['image'].casefold() != witness['image'].casefold()
                    or observed['computer'].casefold() != receipt['computer'].casefold()
                    or int(observed['observed_filetime']) < int(witness['creation_filetime'])
                    or not observed['live_handle_retained']):
                return excluded('kernel-birth-identity-contradiction')
            candidates = [s for s in sources if s['event_id'] == 1
                and s['computer'].casefold() == receipt['computer'].casefold()
                and int(s['data']['ProcessId']) == witness['pid']
                and filetime(s['data']['UtcTime']) // 10000 == int(witness['creation_filetime']) // 10000
                and s['data']['Image'].casefold() == witness['image'].casefold()
                and s['data']['CommandLine'] == witness['command_line']]
            if len(candidates) != 1:
                return excluded('no-exclusive-source-birth-command-identity')
            anchors[role] = candidates[0]
            identities[role] = guid(candidates[0]['data']['ProcessGuid'])
        if receipt['parent']['pid'] == receipt['child']['pid'] or identities['parent'] == identities['child']:
            return excluded('parent-child-identity-collision')
        p, c = anchors['parent'], anchors['child']
        if (guid(c['data']['ParentProcessGuid']) != identities['parent']
                or int(c['data']['ParentProcessId']) != receipt['parent']['pid']
                or c['data']['ParentImage'].casefold() != receipt['parent']['image'].casefold()
                or int(p['data']['ParentProcessId']) != receipt['wrapper']['pid']):
            return excluded('parent-child-lineage-contradiction')
        matches = [role for role, source in anchors.items() if wazuh_matches(alert, source, profile)]
        if len(matches) != 1:
            return excluded('no-exclusive-original-xml-wazuh-copy')
        role = matches[0]
        return {'decision': 'member-verified', 'confidence': 'verified',
            'activity_id': receipt['activity_id'], 'process_role': role,
            'process_guid': identities[role], 'source_record_id': anchors[role]['record_id'],
            'reason': 'launch-witness+independent-kernel-birth+exact-original-Sysmon-Wazuh-lineage',
            'features_updated': False}
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
        return excluded('incomplete-or-conflicting-proof')


def verify_evidence(root):
    """Verifie les fichiers XML rendus et l'export EVTX binaire avant usage."""
    root = Path(root).resolve(); manifest = load_json(root / 'source-manifest.json')
    if not manifest['complete'] or not manifest.get('evtx_xml_verified_on_controller'):
        raise ValueError('collecte Windows incomplete')
    paths = set(); sources = []
    for entry in manifest['files']:
        path = (root / entry['path']).resolve()
        if not path.is_relative_to(root) or path in paths or not path.is_file():
            raise ValueError('chemin absent, duplique ou hors bundle')
        paths.add(path)
        if path.stat().st_size != entry['bytes'] or sha256_file(path) != entry['sha256']:
            raise ValueError('preuve Windows alteree')
        if entry['kind'] == 'event-xml-rendering':
            sources.append(parse_xml(path.read_bytes()))
    if not any(e['kind'] == 'evtx-export' for e in manifest['files']):
        raise ValueError('export EVTX absent')
    if len({event_key(s) for s in sources}) != len(sources):
        raise ValueError('identite evenement source dupliquee')
    return sources
