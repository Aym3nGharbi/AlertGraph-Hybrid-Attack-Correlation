"""Mapping observable AIT/SAGE, indépendant des labels de scénario."""

from __future__ import annotations


# Transcription du fichier sage_mapping.py publié par ait-aecid/alert-data-set.
AIT_SIGNATURE_TO_STAGE = {
    "AMiner: New characters in DNS domain.": "HOST_DISC",
    "AMiner: CPU value out of expected range in monitoring logs.": "BRUTE_FORCE_CREDS",
    "AMiner: New ip address in DNS logs.": "NON_MALICIOUS",
    "AMiner: Unusual occurrence frequencies of Apache Access logs.": "INFO_DISC",
    "AMiner: New cred_disp parameter combination in Audit logs.": "PRIV_ESC",
    "AMiner: New user_cmd parameter combination in Audit logs.": "PRIV_ESC",
    "AMiner: New user_end parameter combination in Audit logs.": "PRIV_ESC",
    "SURICATA HTTP invalid response chunk len": "SERVICE_DISC",
    "AMiner: Unusual occurrence frequencies of query records in DNS logs.": "NON_MALICIOUS",
    "AMiner: New user_auth parameter combination in Audit logs.": "PRIV_ESC",
    "AMiner: New service_start parameter combination in Audit logs.": "PRIV_ESC",
    "CMS (WordPress or Joomla) brute force attempt.": "BRUTE_FORCE_CREDS",
    "SURICATA TLS invalid record type": "USER_PRIV_ESC",
    "CMS (WordPress or Joomla) login attempt.": "SERVICE_DISC",
    "ET INFO Observed DNS Query to .cloud TLD": "NON_MALICIOUS",
    "ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management": "NON_MALICIOUS",
    "AMiner: High entropy in Apache Access request.": "PUBLIC_APP_EXP",
    "SURICATA HTTP unable to match response to request": "NON_MALICIOUS",
    "PAM: User login failed.": "NON_MALICIOUS",
    "Dovecot Invalid User Login Attempt.": "NON_MALICIOUS",
    "AMiner: CPU value deviates from average in monitoring logs.": "BRUTE_FORCE_CREDS",
    "AMiner: Unusual occurrence frequencies of DNS query IPs.": "NON_MALICIOUS",
    "PAM: Login session closed.": "USER_PRIV_ESC",
    "Successful sudo to ROOT executed.": "PRIV_ESC",
    "AMiner: New user_start parameter combination in Audit logs.": "PRIV_ESC",
    "AMiner: New cred_acq parameter combination in Audit logs.": "PRIV_ESC",
    "AMiner: New user_acct parameter combination in Audit logs.": "PRIV_ESC",
    "AMiner: New service_stop parameter combination in Audit logs.": "PRIV_ESC",
    "SURICATA SMTP no server welcome message": "SERVICE_DISC",
    "Suspicious URL access.": "SERVICE_DISC",
    "AMiner: New event type.": "SERVICE_SPECIFIC",
    "AMiner: New request method in Apache Access log.": "SERVICE_DISC",
    "Apache: Attempt to access forbidden file or directory.": "SERVICE_DISC",
    "Apache: Attempt to access forbidden directory index.": "SERVICE_DISC",
    "Web server 400 error code.": "SERVICE_DISC",
    "SURICATA TLS invalid SSLv2 header": "SERVICE_DISC",
    "SURICATA SMTP invalid reply": "SERVICE_DISC",
    "AMiner: New status code in Apache Access log.": "SERVICE_DISC",
    "AMiner: New characters in Apache Access request.": "SERVICE_DISC",
    "Multiple web server 400 error codes from same source ip.": "SERVICE_DISC",
    "AMiner: Unusual occurrence frequencies of Apache Access request methods.": "SERVICE_DISC",
    "Common web attack.": "SERVICE_DISC",
    "PAM: Login session opened.": "USER_PRIV_ESC",
    "User successfully changed UID.": "PRIV_ESC",
    "AMiner: New login parameter combination in Audit logs.": "PRIV_ESC",
    "First time user executed sudo.": "PRIV_ESC",
    "AMiner: New cred_refr parameter combination in Audit logs.": "PRIV_ESC",
    "sshd: insecure connection attempt (scan).": "SERVICE_DISC",
    "Web server 500 error code (Internal Error).": "SERVICE_DISC",
    "syslog: User authentication failure.": "NON_MALICIOUS",
    "SURICATA TLS certificate invalid der": "NON_MALICIOUS",
    "AMiner: New user_login parameter combination in Audit logs.": "PRIV_ESC",
    "sshd: authentication success.": "PRIV_ESC",
    "AMiner: Unusual occurrence frequencies of DNS log events.": "PRIV_ESC",
    "AMiner: High entropy in DNS domain.": "NON_MALICIOUS",
    "ET DNS DNS Lookup for localhost.DOMAIN.TLD": "NON_MALICIOUS",
    "AMiner: Unusual occurrence frequencies of DNS query records.": "DATA_EXFILTRATION",
    "AMiner: New syscall parameter combination in Audit logs.": "PRIV_ESC",
    "ET INFO Session Traversal Utilities for NAT (STUN Binding Request)": "NON_MALICIOUS",
    "First time this IDS alert is generated.": "NON_MALICIOUS",
}


_CASEFOLD_MAPPING = {
    signature.casefold(): stage for signature, stage in AIT_SIGNATURE_TO_STAGE.items()
}


def normalize_signature(signature: str) -> str:
    value = signature.strip()
    for prefix in ("Wazuh: ", "Suricata: Alert - "):
        if value.startswith(prefix):
            value = value[len(prefix) :]
    return value


def observable_stage(signature: str) -> str | None:
    normalized = normalize_signature(signature)
    return _CASEFOLD_MAPPING.get(normalized.casefold())

