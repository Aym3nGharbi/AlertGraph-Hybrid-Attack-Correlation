import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, extname } from 'node:path';

function parseCsv(text) {
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  const headers = lines.shift()?.split(',').map((item) => item.trim()) || [];
  return lines.map((line) => Object.fromEntries(line.split(',').map((value, index) => [headers[index], value.trim()])));
}

export async function readAlerts(path) {
  const text = await readFile(path, 'utf8');
  const extension = extname(path).toLowerCase();
  if (extension === '.jsonl' || extension === '.ndjson') {
    return text.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
  }
  if (extension === '.csv') return parseCsv(text);
  const parsed = JSON.parse(text);
  return Array.isArray(parsed) ? parsed : parsed.alerts;
}

export async function writeJson(path, data) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
}
