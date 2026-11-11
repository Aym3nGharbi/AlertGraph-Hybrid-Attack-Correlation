const PHASE_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact'
];

const PHASE_ALIASES = new Map([
  ['recon', 'reconnaissance'], ['scan', 'reconnaissance'],
  ['accès initial', 'initial-access'], ['initial access', 'initial-access'],
  ['exploitation', 'initial-access'], ['exécution', 'execution'],
  ['élévation de privilèges', 'privilege-escalation'],
  ['privilege escalation', 'privilege-escalation'],
  ['mouvement latéral', 'lateral-movement'], ['lateral movement', 'lateral-movement'],
  ['commande et contrôle', 'command-and-control'], ['c2', 'command-and-control']
]);

export function canonicalPhase(phase) {
  const normalized = String(phase || 'unknown').trim().toLowerCase();
  return PHASE_ALIASES.get(normalized) || normalized.replaceAll('_', '-').replaceAll(' ', '-');
}

function tokens(text) {
  return new Set(String(text || '').toLowerCase().match(/[\p{L}\p{N}]{3,}/gu) || []);
}

function jaccard(a, b) {
  const left = tokens(a);
  const right = tokens(b);
  if (!left.size || !right.size) return 0;
  const intersection = [...left].filter((word) => right.has(word)).length;
  return intersection / (left.size + right.size - intersection);
}

export function minutesBetween(a, b) {
  return Math.abs(new Date(a.timestamp) - new Date(b.timestamp)) / 60000;
}

export function similarityScore(a, b, maxMinutes = 45) {
  const delta = minutesBetween(a, b);
  const temporal = delta <= maxMinutes ? Math.exp(-delta / Math.max(maxMinutes / 3, 1)) : 0;
  const sourceIp = a.sourceIp && a.sourceIp === b.sourceIp ? 1 : 0;
  const destinationIp = a.destinationIp && a.destinationIp === b.destinationIp ? 1 : 0;
  const crossedIp = (a.sourceIp && a.sourceIp === b.destinationIp) ||
    (a.destinationIp && a.destinationIp === b.sourceIp) ? 1 : 0;
  const addressesA = new Set([a.sourceIp, a.destinationIp].filter(Boolean));
  const networkContinuity = [b.sourceIp, b.destinationIp].filter(Boolean).some((ip) => addressesA.has(ip)) ? 1 : 0;
  const host = a.host && a.host === b.host ? 1 : 0;
  const service = a.service && a.service === b.service ? 1 : 0;
  const semantic = jaccard(`${a.eventType} ${a.description}`, `${b.eventType} ${b.description}`);

  const score = 0.35 * networkContinuity + 0.15 * host + 0.10 * service +
    0.15 * semantic + 0.25 * temporal;
  return {
    score: Math.min(1, score),
    components: { sourceIp, destinationIp, crossedIp, networkContinuity, host, service, semantic, temporal }
  };
}

export function causalScore(a, b, maxMinutes = 45) {
  const [earlier, later] = new Date(a.timestamp) <= new Date(b.timestamp) ? [a, b] : [b, a];
  const delta = minutesBetween(a, b);
  if (delta > maxMinutes) return { score: 0, reason: 'outside-time-window' };

  const from = PHASE_ORDER.indexOf(canonicalPhase(earlier.phase));
  const to = PHASE_ORDER.indexOf(canonicalPhase(later.phase));
  if (from < 0 || to < 0) return { score: 0.15, reason: 'unknown-phase' };
  if (from === to) return { score: 0.55, reason: 'same-phase' };
  if (to > from) {
    const distance = to - from;
    return { score: Math.max(0.35, 1 - (distance - 1) * 0.12), reason: 'forward-progression' };
  }
  return { score: 0.05, reason: 'backward-progression' };
}

export function hybridScore(a, b, options = {}) {
  const alpha = options.alpha ?? 0.65;
  const maxMinutes = options.maxTimeDifferenceMinutes ?? 45;
  const similarity = similarityScore(a, b, maxMinutes);
  const causal = causalScore(a, b, maxMinutes);
  return {
    score: alpha * similarity.score + (1 - alpha) * causal.score,
    similarity: similarity.score,
    causal: causal.score,
    evidence: { similarity: similarity.components, causalReason: causal.reason }
  };
}

export { PHASE_ORDER };
