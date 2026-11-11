import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateClustering } from '../src/evaluator.js';

test('calcule les métriques pair-à-pair d’un regroupement parfait', () => {
  const alerts = [{ id: 'a', label: 'x' }, { id: 'b', label: 'x' }, { id: 'c', label: 'y' }, { id: 'd', label: 'y' }];
  const attacks = [{ id: 'p1', alerts: alerts.slice(0, 2) }, { id: 'p2', alerts: alerts.slice(2) }];
  const metrics = evaluateClustering(alerts, attacks);
  assert.equal(metrics.f1, 1);
  assert.equal(metrics.accuracy, 1);
});
