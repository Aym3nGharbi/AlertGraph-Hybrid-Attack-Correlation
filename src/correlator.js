import { hybridScore, minutesBetween, canonicalPhase, PHASE_ORDER } from './scoring.js';

class DisjointSet {
  constructor(size) { this.parent = Array.from({ length: size }, (_, i) => i); }
  find(i) { return this.parent[i] === i ? i : (this.parent[i] = this.find(this.parent[i])); }
  union(a, b) { this.parent[this.find(b)] = this.find(a); }
}

export function correlate(alerts, options = {}) {
  const threshold = options.correlationThreshold ?? 0.52;
  const maxMinutes = options.maxTimeDifferenceMinutes ?? 45;
  const edges = [];
  const sets = new DisjointSet(alerts.length);

  for (let i = 0; i < alerts.length; i += 1) {
    for (let j = i + 1; j < alerts.length; j += 1) {
      if (minutesBetween(alerts[i], alerts[j]) > maxMinutes) continue;
      const result = hybridScore(alerts[i], alerts[j], options);
      if (result.score >= threshold) {
        sets.union(i, j);
        edges.push({ from: alerts[i].id, to: alerts[j].id, ...result });
      }
    }
  }

  const grouped = new Map();
  alerts.forEach((alert, index) => {
    const root = sets.find(index);
    if (!grouped.has(root)) grouped.set(root, []);
    grouped.get(root).push(alert);
  });

  const attacks = [...grouped.values()].map((members, index) => buildAttackGraph(members, edges, index + 1));
  return { attacks, edges, stats: buildStats(alerts, attacks, edges) };
}

function buildAttackGraph(alerts, allEdges, number) {
  const sorted = [...alerts].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  const alertIds = new Set(sorted.map((alert) => alert.id));
  const phases = new Map();

  for (const alert of sorted) {
    const phase = canonicalPhase(alert.phase);
    if (!phases.has(phase)) phases.set(phase, []);
    phases.get(phase).push(alert.id);
  }

  const orderedPhases = [...phases.keys()].sort((a, b) => {
    const ai = PHASE_ORDER.indexOf(a); const bi = PHASE_ORDER.indexOf(b);
    if (ai < 0 && bi < 0) return 0;
    if (ai < 0) return 1; if (bi < 0) return -1;
    return ai - bi;
  });
  const nodes = orderedPhases.map((phase) => ({ id: phase, phase, alertIds: phases.get(phase), count: phases.get(phase).length }));
  const graphEdges = orderedPhases.slice(1).map((phase, index) => ({ from: orderedPhases[index], to: phase }));

  return {
    id: `attack-${number}`,
    startedAt: sorted[0]?.timestamp,
    endedAt: sorted.at(-1)?.timestamp,
    alertCount: sorted.length,
    alerts: sorted,
    correlationEdges: allEdges.filter((edge) => alertIds.has(edge.from) && alertIds.has(edge.to)),
    graph: { nodes, edges: graphEdges }
  };
}

function buildStats(alerts, attacks, edges) {
  return {
    alerts: alerts.length,
    attacks: attacks.length,
    correlatedRelations: edges.length,
    isolatedAlerts: attacks.filter((attack) => attack.alertCount === 1).length
  };
}
