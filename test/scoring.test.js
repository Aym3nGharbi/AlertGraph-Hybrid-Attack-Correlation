import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAlerts } from '../src/normalizer.js';
import { hybridScore, canonicalPhase } from '../src/scoring.js';
import { correlate } from '../src/correlator.js';

const raw = [
  { id: 'a', timestamp: '2026-01-01T10:00:00Z', src_ip: '1.1.1.1', dest_ip: '2.2.2.2', phase: 'reconnaissance' },
  { id: 'b', timestamp: '2026-01-01T10:02:00Z', src_ip: '1.1.1.1', dest_ip: '2.2.2.2', phase: 'initial access' },
  { id: 'c', timestamp: '2026-01-01T14:00:00Z', src_ip: '9.9.9.9', dest_ip: '8.8.8.8', phase: 'execution' }
];

test('normalise les alias de phases', () => {
  assert.equal(canonicalPhase('Initial Access'), 'initial-access');
  assert.equal(canonicalPhase('élévation de privilèges'), 'privilege-escalation');
});

test('attribue un score fort aux alertes proches et cohérentes', () => {
  const [a, b] = normalizeAlerts(raw);
  const result = hybridScore(a, b, { alpha: 0.65, maxTimeDifferenceMinutes: 45 });
  assert.ok(result.score > 0.52);
  assert.equal(result.evidence.causalReason, 'forward-progression');
});

test('sépare les alertes éloignées dans le temps', () => {
  const alerts = normalizeAlerts(raw);
  const result = correlate(alerts, { alpha: 0.65, correlationThreshold: 0.52, maxTimeDifferenceMinutes: 45 });
  assert.equal(result.attacks.length, 2);
  assert.equal(result.attacks.find((attack) => attack.alertCount === 2).alertCount, 2);
});
