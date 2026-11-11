import http from 'node:http';
import { readFile, readdir } from 'node:fs/promises';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runPipeline } from './pipeline.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const publicDirectory = join(root, 'public');
const labRunsDirectory = join(root, 'lab', 'runs');
const port = Number(process.env.PORT || 8080);
const staticFiles = new Map([['/', 'index.html'], ['/index.html', 'index.html'], ['/app.js', 'app.js'], ['/styles.css', 'styles.css']]);
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
const rawAlertCache = new Map();
const visibleLabRuns = [
  'dev-linux-auth-fim-20261101-001',
  'dev-linux-distinct-attacks-20261101-001',
];

function validateRunId(runId) {
  if (!/^[a-zA-Z0-9._-]+$/.test(runId)) throw new Error('Identifiant de run invalide');
}

async function labRunFile(runId) {
  validateRunId(runId);
  const entries = await readdir(join(labRunsDirectory, runId), { withFileTypes: true });
  const inference = entries.filter((item) => item.isDirectory() && item.name.startsWith('inference')).map((item) => item.name).sort().at(-1);
  if (!inference) throw new Error('Aucune inférence pour ce run');
  return join(labRunsDirectory, runId, inference, 'visualization.json');
}

async function rawAlert(runId, alertId) {
  validateRunId(runId);
  if (!alertId || alertId.length > 256 || /[\r\n]/.test(alertId)) throw new Error('Identifiant d’alerte invalide');
  if (!rawAlertCache.has(runId)) {
    const content = await readFile(join(labRunsDirectory, runId, 'alerts.jsonl'), 'utf8');
    const index = new Map();
    for (const line of content.split(/\r?\n/).filter(Boolean)) {
      const alert = JSON.parse(line);
      index.set(String(alert.id), alert);
    }
    rawAlertCache.set(runId, index);
  }
  return rawAlertCache.get(runId).get(alertId) ?? null;
}

async function listLabRuns() {
  const runs = [];
  for (const runId of visibleLabRuns) {
    try {
      const document = JSON.parse(await readFile(await labRunFile(runId), 'utf8'));
      runs.push({ id: runId, nodes: document.nodes.length });
    } catch (error) { console.warn(`Run ignoré (${runId}): ${error.message}`); }
  }
  return runs;
}

async function loadLabRun(runId, includeEvaluation = false) {
  const document = JSON.parse(await readFile(await labRunFile(runId), 'utf8'));
  if (!includeEvaluation) return document;
  const candidates = ['evaluation-episode-hard.json', 'evaluation-episode.json', 'evaluation-provisional-v2.json', 'evaluation-provisional.json'];
  for (const name of candidates) {
    try {
      document.evaluation = JSON.parse(await readFile(join(labRunsDirectory, runId, name), 'utf8'));
      document.evaluationFile = name;
      break;
    } catch { /* L'évaluation est optionnelle. */ }
  }
  return document;
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, 'http://127.0.0.1');
    const pathname = url.pathname;
    if (pathname === '/api/report') {
      const report = await runPipeline(join(root, 'data', 'demo-alerts.json'), join(root, 'config', 'default.json'));
      response.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' }); response.end(JSON.stringify(report)); return;
    }
    if (pathname === '/api/lab/runs') {
      response.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      response.end(JSON.stringify(await listLabRuns())); return;
    }
    const rawMatch = pathname.match(/^\/api\/lab\/runs\/([a-zA-Z0-9._-]+)\/raw-alerts\/(.+)$/);
    if (rawMatch) {
      const alert = await rawAlert(rawMatch[1], decodeURIComponent(rawMatch[2]));
      response.writeHead(alert ? 200 : 404, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      response.end(JSON.stringify(alert ?? { error: 'Alerte brute introuvable' })); return;
    }
    const labMatch = pathname.match(/^\/api\/lab\/runs\/([a-zA-Z0-9._-]+)$/);
    if (labMatch) {
      response.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      response.end(JSON.stringify(await loadLabRun(labMatch[1], url.searchParams.get('mode') === 'evaluation'))); return;
    }
    const file = staticFiles.get(pathname);
    if (!file) { response.writeHead(404); response.end('Not found'); return; }
    const content = await readFile(join(publicDirectory, file));
    response.writeHead(200, { 'Content-Type': mime[extname(file)] }); response.end(content);
  } catch (error) {
    response.writeHead(500, { 'Content-Type': 'application/json' }); response.end(JSON.stringify({ error: error.message }));
  }
});

server.listen(port, '127.0.0.1', () => console.log(`Interface disponible sur http://127.0.0.1:${port}`));
