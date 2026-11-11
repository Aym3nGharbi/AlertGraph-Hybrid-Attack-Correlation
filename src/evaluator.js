export function evaluateClustering(alerts, attacks) {
  const predictedGroup = new Map();
  attacks.forEach((attack) => attack.alerts.forEach((alert) => predictedGroup.set(alert.id, attack.id)));
  let truePositive = 0; let falsePositive = 0; let falseNegative = 0; let trueNegative = 0; let evaluatedPairs = 0;
  for (let i = 0; i < alerts.length; i += 1) {
    for (let j = i + 1; j < alerts.length; j += 1) {
      if (!alerts[i].label || !alerts[j].label) continue;
      evaluatedPairs += 1;
      const sameTruth = alerts[i].label === alerts[j].label;
      const samePrediction = predictedGroup.get(alerts[i].id) === predictedGroup.get(alerts[j].id);
      if (sameTruth && samePrediction) truePositive += 1;
      else if (!sameTruth && samePrediction) falsePositive += 1;
      else if (sameTruth && !samePrediction) falseNegative += 1;
      else trueNegative += 1;
    }
  }
  if (!evaluatedPairs) return { available: false, reason: 'Aucun label de vérité terrain exploitable' };
  const precision = truePositive / Math.max(truePositive + falsePositive, 1);
  const recall = truePositive / Math.max(truePositive + falseNegative, 1);
  const f1 = 2 * precision * recall / Math.max(precision + recall, Number.EPSILON);
  const accuracy = (truePositive + trueNegative) / evaluatedPairs;
  return { available: true, evaluatedPairs, confusion: { truePositive, falsePositive, falseNegative, trueNegative }, precision, recall, f1, accuracy };
}
