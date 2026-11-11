"""Exécute une commande WinRM bénigne et produit un reçu V1 adaptable."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .clock_audit import require_clock_ready
from .io_utils import load_json, write_new_json
from .prepare_campaign import verify_campaign_reservation


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _planned_activity(plan: Mapping[str, object], activity_key: str) -> Mapping[str, object]:
    matches = [x for x in plan["activities"] if x["activity_key"] == activity_key]
    if len(matches) != 1:
        raise ValueError(f"Activité planifiée introuvable ou ambiguë: {activity_key}")
    activity = matches[0]
    if activity["class"] != "benign" or activity["platform"] != "windows":
        raise ValueError("Ce runner accepte uniquement une activité Windows bénigne")
    return activity


def run_benign_winrm_activity(
    campaign_dir: str | Path,
    *,
    activity_key: str,
    computer_name: str,
    credential_file: str | Path,
    receipt_filename: str = "v1-truth.json",
) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    manifest = verify_campaign_reservation(campaign_dir)
    if manifest["partition"] != "development":
        raise PermissionError("Le runner pilote exige la partition development")
    require_clock_ready(campaign_dir)
    plan = load_json(campaign_dir / "campaign-plan.json")
    activity = _planned_activity(plan, activity_key)
    if computer_name not in activity["target_hosts"]:
        raise ValueError("Hôte WinRM absent du plan scellé")
    credential_file = Path(credential_file)
    if not credential_file.is_file():
        raise FileNotFoundError("Credential WinRM DPAPI absent")
    if Path(receipt_filename).name != receipt_filename or not receipt_filename.endswith(".json"):
        raise ValueError("receipt_filename doit être un simple nom JSON")

    marker = str(activity["marker_id"])
    script = r"""
$ErrorActionPreference='Stop'
$cred=Import-Clixml -LiteralPath '__CREDENTIAL__'
$remote=Invoke-Command -ComputerName '__COMPUTER__' -UseSSL -Authentication Negotiate -Credential $cred -ArgumentList '__MARKER__' -ScriptBlock {
  param($Marker)
  $started=[DateTimeOffset]::UtcNow
  $psi=[System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName="$env:SystemRoot\System32\cmd.exe"
  $psi.Arguments="/d /c echo $Marker"
  $psi.UseShellExecute=$false
  $psi.CreateNoWindow=$true
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $process=[System.Diagnostics.Process]::Start($psi)
  $processId=$process.Id
  $stdout=$process.StandardOutput.ReadToEnd()
  $stderr=$process.StandardError.ReadToEnd()
  $process.WaitForExit()
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $logonSid=$identity.Groups | Where-Object { $_.Value -like 'S-1-5-5-*' } | Select-Object -First 1
  $logonId=$null
  if($null -ne $logonSid){
    $parts=$logonSid.Value.Split('-')
    if($parts.Count -ge 2){
      $high=[uint64]$parts[$parts.Count-2]
      $low=[uint64]$parts[$parts.Count-1]
      $logonId=('0x{0:x}' -f (($high -shl 32) -bor $low))
    }
  }
  [ordered]@{
    target_started_at_utc=$started.ToString('o')
    target_ended_at_utc=[DateTimeOffset]::UtcNow.ToString('o')
    process_id=[int]$processId
    parent_process_id=[int]$PID
    image="$env:SystemRoot\System32\cmd.exe"
    command_line="cmd.exe /d /c echo $Marker"
    user=$identity.Name
    logon_sid=if($null -ne $logonSid){$logonSid.Value}else{$null}
    logon_id=$logonId
    session_id=[int]([System.Diagnostics.Process]::GetCurrentProcess().SessionId)
    computer=$env:COMPUTERNAME
    exit_code=[int]$process.ExitCode
    stdout=$stdout.Trim()
    stderr=$stderr.Trim()
  }
}
$remote | ConvertTo-Json -Depth 4 -Compress
"""
    escaped_credential = str(credential_file.resolve()).replace("'", "''")
    script = (
        script.replace("__CREDENTIAL__", escaped_credential)
        .replace("__COMPUTER__", computer_name)
        .replace("__MARKER__", marker)
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    started = _utc_now()
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True,
        timeout=30,
        check=False,
    )
    ended = _utc_now()
    if completed.returncode != 0:
        raise RuntimeError("L'activité WinRM contrôlée a échoué")
    try:
        target = json.loads(completed.stdout.decode("utf-8-sig").strip())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Reçu JSON WinRM invalide") from exc
    if target.get("stdout") != marker or int(target.get("exit_code", -1)) != 0:
        raise ValueError("Le marqueur WinRM n'a pas été retourné exactement")

    step = {
        "name": activity["activity_name"],
        "ground_truth_phase": activity.get("true_activity_phase"),
        "started_at": started,
        "ended_at": ended,
        "target_started_at_utc": target["target_started_at_utc"],
        "target_ended_at_utc": target["target_ended_at_utc"],
        "exit_code": 0,
        "result": {
            "platform": "windows",
            "operation": "controlled-legitimate-winrm-echo",
            "transport": "winrm-https",
            "target_process_id": int(target["process_id"]),
            "target_parent_process_id": int(target["parent_process_id"]),
            "target_image": target["image"],
            "target_command_line": target["command_line"],
            "target_user": target["user"],
            "target_computer": target["computer"],
            "target_logon_sid": target.get("logon_sid"),
            "target_logon_id": target.get("logon_id"),
            "target_session_id": int(target["session_id"]),
            "marker_echoed": True,
            "stdout_sha256": hashlib.sha256(target["stdout"].encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(target["stderr"].encode()).hexdigest(),
        },
    }
    receipt = {"status": "completed", "steps": [step]}
    receipt_path = campaign_dir / "receipts" / receipt_filename
    write_new_json(receipt_path, receipt)
    return {"receipt": str(receipt_path), "step": step}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--activity-key", required=True)
    parser.add_argument("--computer-name", required=True)
    parser.add_argument("--credential-file", required=True, type=Path)
    parser.add_argument("--receipt-filename", default="v1-truth.json")
    args = parser.parse_args()
    print(json.dumps(run_benign_winrm_activity(
        args.campaign_dir,
        activity_key=args.activity_key,
        computer_name=args.computer_name,
        credential_file=args.credential_file,
        receipt_filename=args.receipt_filename,
    ), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
