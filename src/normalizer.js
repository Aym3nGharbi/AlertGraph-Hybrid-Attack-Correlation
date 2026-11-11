const first = (...values) => values.find((value) => value !== undefined && value !== null && value !== '');

function cleanIp(value) {
  if (value === undefined || value === null) return null;
  return String(value).trim().replace(/^::ffff:/, '') || null;
}

function cleanText(value) {
  return value === undefined || value === null ? '' : String(value).trim();
}

export function normalizeAlert(raw, index = 0) {
  const timestampValue = first(raw.timestamp, raw['@timestamp'], raw.time, raw.event_time);
  const timestamp = new Date(timestampValue);
  if (!timestampValue || Number.isNaN(timestamp.getTime())) {
    throw new Error(`Alerte ${index}: timestamp absent ou invalide`);
  }

  return {
    id: cleanText(first(raw.id, raw.alert_id, raw._id, `alert-${index + 1}`)),
    timestamp: timestamp.toISOString(),
    source: cleanText(first(raw.source, raw.sensor, raw.agent?.name, raw.observer?.name, 'unknown')),
    sourceIp: cleanIp(first(raw.sourceIp, raw.src_ip, raw.srcip, raw.source?.ip, raw.data?.srcip)),
    destinationIp: cleanIp(first(raw.destinationIp, raw.dest_ip, raw.dst_ip, raw.destination?.ip, raw.data?.dstip)),
    host: cleanText(first(raw.host, raw.hostname, raw.agent?.name, raw.host?.name)),
    service: cleanText(first(raw.service, raw.protocol, raw.app_proto, raw.network?.protocol)).toLowerCase(),
    eventType: cleanText(first(raw.eventType, raw.event_type, raw.signature, raw.rule?.description, raw.name)),
    description: cleanText(first(raw.description, raw.message, raw.full_log, raw.alert?.signature)),
    phase: cleanText(first(raw.phase, raw.attack_phase, raw.mitre_tactic, raw.rule?.mitre?.tactic?.[0], 'unknown')).toLowerCase(),
    severity: Number(first(raw.severity, raw.level, raw.rule?.level, 0)) || 0,
    label: cleanText(first(raw.label, raw.attack_id, raw.scenario_id)) || null,
    raw
  };
}

export function normalizeAlerts(alerts) {
  if (!Array.isArray(alerts)) throw new Error('Le document d’entrée doit contenir un tableau d’alertes');
  return alerts.map(normalizeAlert);
}
