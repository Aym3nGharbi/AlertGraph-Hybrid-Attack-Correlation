"""Runner Windows V2 : aperçu sans réseau par défaut ; aucun retry."""
from datetime import datetime, timezone, timedelta
from pathlib import Path
import argparse
import json
import shlex
import shutil
import subprocess

from .prepare import validate
from ..clock_audit import require_clock_ready
from ..io_utils import load_json, write_new_json, sha256_file, utc_now
from .ssh_readonly import ssh_base as _ssh_base
from ..ssh_collection import collect_ssh_campaign, SubprocessSSHRunner


def manager_guard(key):
    code = "import os,json,sqlite3,shutil; d=sqlite3.connect('file:/var/ossec/queue/db/global.db?mode=ro',uri=True); p='/var/ossec/logs/alerts/alerts.json'; print(json.dumps({'agents':d.execute('select connection_status from agent where name=?',('windows-agent',)).fetchall(),'readable':os.access(p,os.R_OK),'bytes':os.stat(p).st_size,'free_bytes':shutil.disk_usage('/var/ossec').free}))"
    result = subprocess.run([*_ssh_base('192.0.2.10','labuser',key), 'python3 -c ' + shlex.quote(code)], capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError('lecture Manager impossible')
    value = json.loads(result.stdout)
    if value['agents'] != [['active']] or not value['readable'] or value['bytes'] > 25 * 1024**2 or min(value['free_bytes'], shutil.disk_usage('.').free) < 5 * 1024**3:
        raise RuntimeError('agent ou ressources Manager non conformes')
    return value


def run(campaign, *, credential_file=None, key=None, execute_authorized=False):
    campaign = Path(campaign); plan, manifest, protocol = validate(campaign)
    if not execute_authorized:
        return {'mode':'preview-only','parent_child_activity':'gated read-only username query',
            'network_action_executed':False,'execution_authorized':False,'training_ready':False}
    for name in ('windows-execution','windows-analysis','raw'):
        if (campaign / name).exists():
            raise FileExistsError('run deja utilise: ' + name)
    if not credential_file or not key or not Path(credential_file).is_file() or not Path(key).is_file():
        raise FileNotFoundError('acces locaux requis absents')
    clock = require_clock_ready(campaign)
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(clock['created_at_utc'])).total_seconds()
    if not 0 <= age <= 120 or not {'controller','wazuh-manager','windows-target'} <= {m['role'] for m in clock['measurements']}:
        raise RuntimeError('audit frais des participants requis, age maximal 120s')
    manager_guard(Path(key))
    execution = campaign / 'windows-execution'
    command = ['powershell.exe','-NoProfile','-NonInteractive','-File',str(Path(__file__).with_name('orchestrate.ps1')),
        '-ComputerName',protocol['host'],'-CredentialFile',str(credential_file),'-RunId',manifest['run_id'],
        '-OutputDirectory',str(execution),'-ExecuteAuthorized']
    try:
        result = subprocess.run(command, capture_output=True, timeout=90)
        # Pas de copie du chemin de credential ou des erreurs de connexion en clair.
        from ..io_utils import write_new_bytes
        write_new_bytes(execution / 'controller-stdout.bin', result.stdout)
        write_new_json(execution / 'controller-command-result.json', {'exit_code':result.returncode,
            'stderr_sha256':__import__('hashlib').sha256(result.stderr).hexdigest(),'stderr_bytes':len(result.stderr),
            'training_ready':False})
        if result.returncode:
            raise RuntimeError('orchestrateur Windows en echec; aucun retry')
        files={str(p.relative_to(execution)):sha256_file(p) for p in execution.rglob('*') if p.is_file()}
        write_new_json(execution / 'execution-seal.json', {'files_sha256':files,'training_ready':False})
        manager_guard(Path(key))
        receipt = load_json(execution / 'controller-receipt.json')
        begin=datetime.fromisoformat(receipt['started_at_utc'])-timedelta(seconds=2)
        end=datetime.fromisoformat(receipt['ended_at_utc'])+timedelta(seconds=12)
        collect_ssh_campaign(campaign,host='192.0.2.10',user='labuser',key=key,
            since=begin.timestamp(),until=end.timestamp(),agents={protocol['agent_name']},
            runner=SubprocessSSHRunner(),allow_remote_read=True)
        from .analysis import analyze
        return analyze(campaign)
    except Exception as exc:
        write_new_json(execution / 'runner-failure.json', {'created_at_utc':utc_now(),'error_type':type(exc).__name__,
            'repeat_authorized':False,'remote_cleanup_not_inferred':True,'training_ready':False})
        raise


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('campaign',type=Path)
    parser.add_argument('--credential-file',type=Path)
    parser.add_argument('--key',type=Path)
    parser.add_argument('--execute-authorized',action='store_true')
    print(json.dumps(run(**vars(parser.parse_args())),indent=2))
