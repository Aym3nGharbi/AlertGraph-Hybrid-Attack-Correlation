#!/usr/bin/env node
import { runPipeline } from './pipeline.js';
import { writeJson } from './io.js';

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

const input = argument('--input');
const output = argument('--output', 'output/report.json');
const config = argument('--config', 'config/default.json');

if (!input) {
  console.error('Usage: node src/cli.js --input <alertes.json|jsonl|csv> [--output rapport.json]');
  process.exit(1);
}

try {
  const report = await runPipeline(input, config);
  await writeJson(output, report);
  console.log(`Rapport créé: ${output}`);
  console.log(`${report.stats.alerts} alertes, ${report.stats.attacks} groupes, ${report.stats.correlatedRelations} relations`);
} catch (error) {
  console.error(`Erreur: ${error.message}`);
  process.exit(1);
}
