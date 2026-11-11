import { readFile } from 'node:fs/promises';
import { normalizeAlerts } from './normalizer.js';
import { correlate } from './correlator.js';
import { evaluateClustering } from './evaluator.js';
import { readAlerts } from './io.js';

export async function loadConfig(path = 'config/default.json') {
  return JSON.parse(await readFile(path, 'utf8'));
}

export async function runPipeline(inputPath, configPath) {
  const [rawAlerts, config] = await Promise.all([readAlerts(inputPath), loadConfig(configPath)]);
  const alerts = normalizeAlerts(rawAlerts);
  const result = correlate(alerts, config);
  return { generatedAt: new Date().toISOString(), config, ...result, evaluation: evaluateClustering(alerts, result.attacks) };
}
