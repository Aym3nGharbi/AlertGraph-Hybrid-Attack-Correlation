const method = 'episode_constrained_bridges';
const runLabels = {
  'dev-linux-auth-fim-20261101-001': 'Une attaque contrôlée',
  'dev-linux-distinct-attacks-20261101-001': 'Deux attaques distinctes',
};
const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[character]));
const stageLabel = (stage) => stage ? stage.replaceAll('_', ' ').toLowerCase() : 'non mappé';
const formatTime = (seconds) => new Date(seconds * 1000).toLocaleString('fr-FR');
const number = (value, digits = 3) => value === null || value === undefined ? '—' : Number(value).toFixed(digits);
let documentRun;
let selectedComponent = null;

function groups() {
  const result = new Map();
  for (const node of documentRun.nodes) {
    const component = node.components[method];
    if (!result.has(component)) result.set(component, []);
    result.get(component).push(node);
  }
  return [...result.entries()].map(([component, nodes]) => {
    nodes.sort((a, b) => a.first_timestamp - b.first_timestamp);
    const ids = new Set(nodes.map((node) => node.id));
    const relations = (documentRun.edges[method] ?? []).filter((edge) => ids.has(edge.from) && ids.has(edge.to));
    return { component, nodes, relations };
  }).sort((a, b) => b.nodes.length - a.nodes.length || a.nodes[0].first_timestamp - b.nodes[0].first_timestamp);
}

function renderSummary(items) {
  const trace = documentRun.report.traceability;
  const isolated = items.filter((item) => item.nodes.length === 1).length;
  const suspicious = items.length - isolated;
  document.querySelector('#summary').innerHTML = [
    ['Attaques probables', suspicious],
    ['Alertes isolées', isolated],
    ['Événements Wazuh', trace.raw_alerts],
  ].map(([label, value]) => `<div><strong>${escapeHtml(value)}</strong><span>${label}</span></div>`).join('');
  document.querySelector('#incident-count').textContent = `${suspicious} attaque(s) probable(s) · ${isolated} isolée(s)`;
  document.querySelector('#status').textContent = '';
}

async function showRawAlert(alertId) {
  const response = await fetch(`/api/lab/runs/${encodeURIComponent(documentRun.run_id)}/raw-alerts/${encodeURIComponent(alertId)}`);
  if (!response.ok) throw new Error(`événement brut ${alertId} introuvable`);
  const alert = await response.json(); const rule = alert.rule ?? {}; const agent = alert.agent ?? {}; const data = alert.data ?? {};
  document.querySelector('#raw-summary').innerHTML = `<span class="eyebrow">ÉVÉNEMENT WAZUH OBSERVÉ</span><h2>${escapeHtml(rule.description ?? 'Alerte Wazuh')}</h2><div class="raw-facts"><span>ID <b>${escapeHtml(alert.id)}</b></span><span>Règle <b>${escapeHtml(rule.id ?? '—')}</b></span><span>Niveau <b>${escapeHtml(rule.level ?? '—')}</b></span><span>Agent <b>${escapeHtml(agent.name ?? '—')}</b></span><span>Horodatage <b>${escapeHtml(alert.timestamp ?? '—')}</b></span><span>Réseau <b>${escapeHtml(data.srcip ?? '—')} → ${escapeHtml(data.dstip ?? '—')}</b></span></div>`;
  document.querySelector('#raw-json').textContent = JSON.stringify(alert, null, 2);
  document.querySelector('#raw-dialog').showModal();
}

function metaDetails(node) {
  const details = document.createElement('div'); details.className = 'meta-details';
  const tactics = node.observed_tactics.length ? node.observed_tactics.join(', ') : 'aucune';
  details.innerHTML = `<div class="evidence-grid"><div><span>Observation Wazuh</span><b>${escapeHtml(node.signature)}</b><small>${escapeHtml(node.agents.join(', ') || 'agent inconnu')} · ${escapeHtml(formatTime(node.first_timestamp))}</small></div><div><span>Interprétation du corrélateur</span><b>${escapeHtml(stageLabel(node.stage))}</b><small>MITRE fourni par la règle: ${escapeHtml(tactics)} — indication, non confirmation.</small></div></div><div class="raw-access"><label>Événement brut<select>${node.member_alert_ids.map((id) => `<option value="${escapeHtml(id)}">${escapeHtml(id)}</option>`).join('')}</select></label><button type="button">Ouvrir l’événement</button><span>${node.member_count} événement(s) brut(s) disponible(s)</span></div>`;
  const select = details.querySelector('select');
  details.querySelector('button').addEventListener('click', async () => {
    try { await showRawAlert(select.value); } catch (error) { document.querySelector('#status').textContent = `Erreur: ${error.message}`; }
  });
  return details;
}

function renderMetas(container, nodes, stage) {
  container.replaceChildren();
  const filtered = nodes.filter((node) => (node.stage ?? '__unknown__') === stage);
  const heading = document.createElement('div'); heading.className = 'subheading';
  heading.innerHTML = `<div><span class="eyebrow">MÉTA-ALERTES</span><h3>${escapeHtml(stageLabel(stage === '__unknown__' ? null : stage))}</h3></div><span>${filtered.length} résultat(s)</span>`;
  container.append(heading);
  for (const node of filtered) {
    const item = document.createElement('article'); item.className = 'meta-row';
    const severity = node.severity.max ?? node.severity.min ?? '—';
    item.innerHTML = `<button type="button" class="meta-toggle"><span><b>${escapeHtml(node.description)}</b><small>${escapeHtml(node.agents.join(', ') || 'agent inconnu')} · niveau ${escapeHtml(severity)}</small></span><span class="meta-count">${node.member_count} événement(s)<i>›</i></span></button>`;
    const button = item.querySelector('button');
    button.addEventListener('click', () => {
      const existing = item.querySelector('.meta-details');
      if (existing) { existing.remove(); button.classList.remove('open'); return; }
      item.append(metaDetails(node)); button.classList.add('open');
    });
    container.append(item);
  }
}

function renderDetail(item, rank) {
  selectedComponent = item.component;
  document.querySelectorAll('.incident-item').forEach((button) => button.classList.toggle('active', Number(button.dataset.component) === item.component));
  const detail = document.querySelector('#detail'); detail.replaceChildren();
  const rawCount = item.nodes.reduce((sum, node) => sum + node.member_count, 0);
  const type = item.nodes.length === 1 ? 'Alerte isolée' : 'Attaque probable';
  const header = document.createElement('div'); header.className = 'detail-head';
  header.innerHTML = `<div><span class="eyebrow">${escapeHtml(type.toUpperCase())} ${rank + 1}</span><h2>${rawCount} événement(s) · ${item.nodes.length} méta-alerte(s)</h2><p>${escapeHtml(formatTime(item.nodes[0].first_timestamp))} → ${escapeHtml(formatTime(item.nodes.at(-1).last_timestamp))}</p></div><div class="relation-count"><strong>${item.relations.length}</strong><span>relations prédites</span></div>`;
  const phaseSection = document.createElement('section'); phaseSection.className = 'phase-section';
  phaseSection.innerHTML = '<div class="subheading"><div><span class="eyebrow">ACTIVITÉS</span><h3>Catégories de progression inférées</h3></div><span>Cliquez pour examiner</span></div>';
  const phaseList = document.createElement('div'); phaseList.className = 'phase-list';
  const metaContainer = document.createElement('div'); metaContainer.className = 'meta-container';
  const stages = [...new Set(item.nodes.map((node) => node.stage ?? '__unknown__'))];
  for (const stage of stages) {
    const nodes = item.nodes.filter((node) => (node.stage ?? '__unknown__') === stage);
    const button = document.createElement('button'); button.type = 'button'; button.className = 'phase-item';
    button.innerHTML = `<span><i class="dot inferred"></i><b>${escapeHtml(stageLabel(stage === '__unknown__' ? null : stage))}</b></span><small>${nodes.length} méta-alerte(s)</small>`;
    button.addEventListener('click', () => {
      phaseList.querySelectorAll('button').forEach((candidate) => candidate.classList.toggle('active', candidate === button));
      renderMetas(metaContainer, item.nodes, stage);
    });
    phaseList.append(button);
  }
  phaseSection.append(phaseList, metaContainer); detail.append(header, phaseSection);
}

function renderIncidents(items) {
  const list = document.querySelector('#incident-list'); list.replaceChildren();
  items.forEach((item, rank) => {
    const rawCount = item.nodes.reduce((sum, node) => sum + node.member_count, 0);
    const type = item.nodes.length === 1 ? 'Alerte isolée' : 'Attaque probable';
    const stages = [...new Set(item.nodes.map((node) => stageLabel(node.stage)))].slice(0, 3);
    const button = document.createElement('button'); button.type = 'button'; button.className = 'incident-item'; button.dataset.component = item.component;
    button.innerHTML = `<span class="incident-type">${escapeHtml(type)} ${rank + 1}</span><strong>${rawCount} événement(s)</strong><span class="incident-time">${escapeHtml(formatTime(item.nodes[0].first_timestamp))}</span><span class="stage-preview">${stages.map((stage) => `<i>${escapeHtml(stage)}</i>`).join('')}</span>`;
    button.addEventListener('click', () => renderDetail(item, rank)); list.append(button);
  });
}

function render() {
  selectedComponent = null;
  const items = groups();
  renderSummary(items); renderIncidents(items);
  document.querySelector('#detail').innerHTML = '<div class="empty-state"><span class="empty-icon">⌁</span><h2>Sélectionnez une attaque probable</h2><p>Les activités, méta-alertes et événements Wazuh apparaîtront ici à la demande.</p></div>';
}

async function loadRun(id) {
  const response = await fetch(`/api/lab/runs/${encodeURIComponent(id)}`);
  if (!response.ok) throw new Error(`run ${id} indisponible`);
  documentRun = await response.json(); render();
}

try {
  const runs = await (await fetch('/api/lab/runs')).json();
  if (!runs.length) throw new Error('aucun run Wazuh analysé');
  const select = document.querySelector('#run');
  select.innerHTML = runs.map((run) => `<option value="${escapeHtml(run.id)}">${escapeHtml(runLabels[run.id] ?? run.id)}</option>`).join('');
  select.addEventListener('change', () => loadRun(select.value));
  document.querySelector('#copy-json').addEventListener('click', () => navigator.clipboard.writeText(document.querySelector('#raw-json').textContent));
  await loadRun(runs[0].id);
} catch (error) {
  document.querySelector('#status').textContent = `Erreur: ${error.message}`;
}
