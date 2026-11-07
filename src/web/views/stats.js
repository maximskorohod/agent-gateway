// Страница «Активность»: сколько вызовов и заявок у каждого агента и ключа за период, последние вызовы.
import { html, raw, layout, enc, fmtDate, plural, keyName } from './html.js';
import { t, locale } from '../../i18n.js';

export const STATS_PERIODS = [[1, 'stats.period_1'], [7, 'stats.period_7'], [30, 'stats.period_30']];

const num = (n) => Number(n || 0).toLocaleString(locale);

/** Сворачивает строки (agent_id, credential_id, …) в итоги по ключу keyOf. */
function sumBy(rows, keyOf, fields) {
  const out = new Map();
  for (const r of rows) {
    const k = keyOf(r);
    const acc = out.get(k) ?? Object.fromEntries(fields.map((f) => [f, 0]));
    for (const f of fields) acc[f] = f === 'last_at' ? Math.max(acc[f], r[f] ?? 0) : acc[f] + Number(r[f] || 0);
    out.set(k, acc);
  }
  return out;
}

function periodNav(days, agentId) {
  const q = agentId ? `&agent=${enc(agentId)}` : '';
  return html`<nav class="seg" aria-label="${t('stats.period')}">
      ${STATS_PERIODS.map(([d, l]) => html`<a href="/stats?d=${d}${raw(q)}"${d === days ? raw(' aria-current="page"') : ''}>${t(l)}</a>`)}
    </nav>`;
}

function bar(value, max) {
  return html`<meter class="bar" min="0" max="${Math.max(max, 1)}" value="${value}" aria-hidden="true"></meter>`;
}

function statusText(s) {
  const n = Number(s || 0);
  return n ? String(n) : t('stats.no_response');
}

/**
 * calls / requests — строки repo.callStats / repo.requestStats, recent — repo.listCalls.
 * agents, credentials — для имён (включая удалённые ключи: показываем id).
 */
export function statsPage({ csrf, days = 7, agentId = null, calls = [], requests = [], recent = [], agents = [], credentials = [], providers = [] } = {}) {
  const agentName = (id) => agents.find((a) => a.id === id)?.name ?? id ?? '—';
  const credName = (id) => {
    const c = credentials.find((x) => x.id === id);
    return c ? keyName(c, providers) : (id ? t('stats.deleted_key', { id }) : '—');
  };
  const credIcon = (id) => credentials.find((c) => c.id === id)?.provider ?? 'other';

  const byAgentCalls = sumBy(calls, (r) => r.agent_id, ['calls', 'errors', 'last_at']);
  const byAgentReq = sumBy(requests, (r) => r.agent_id, ['total', 'approved', 'denied', 'unanswered']);
  const byCred = sumBy(calls, (r) => r.credential_id, ['calls', 'errors', 'last_at']);

  const agentIds = [...new Set([...byAgentCalls.keys(), ...byAgentReq.keys()])]
    .sort((a, b) => (byAgentCalls.get(b)?.calls ?? 0) - (byAgentCalls.get(a)?.calls ?? 0));
  const credIds = [...byCred.keys()].sort((a, b) => byCred.get(b).calls - byCred.get(a).calls);
  const maxAgent = Math.max(0, ...agentIds.map((id) => byAgentCalls.get(id)?.calls ?? 0));
  const maxCred = Math.max(0, ...credIds.map((id) => byCred.get(id).calls));

  const totalCalls = calls.reduce((s, r) => s + Number(r.calls || 0), 0);
  const totalErrors = calls.reduce((s, r) => s + Number(r.errors || 0), 0);
  const totalReq = requests.reduce((s, r) => s + Number(r.total || 0), 0);
  const totalDenied = requests.reduce((s, r) => s + Number(r.denied || 0), 0);

  const title = agentId ? t('stats.title_agent', { name: agentName(agentId) }) : t('nav.activity');
  return layout(title, html`
    <div class="stats-head">
      ${periodNav(days, agentId)}
      ${agentId ? html`<a class="small" href="/stats?d=${days}">${t('stats.all_agents')}</a>` : ''}
    </div>

    <dl class="kpis">
      <div><dt>${t('stats.kpi_calls')}</dt><dd>${num(totalCalls)}</dd></div>
      <div><dt>${t('stats.kpi_errors')}</dt><dd>${num(totalErrors)}</dd>${totalCalls ? html`<p class="hint">${t('stats.pct_of_all', { pct: Math.round((totalErrors / totalCalls) * 100) })}</p>` : ''}</div>
      <div><dt>${t('stats.kpi_requests')}</dt><dd>${num(totalReq)}</dd>${totalDenied ? html`<p class="hint">${t('stats.denied_n', { n: num(totalDenied) })}</p>` : ''}</div>
    </dl>

    ${agentIds.length || credIds.length ? html`
      ${agentId ? '' : html`
      <section>
        <h2>${t('stats.by_agent')}</h2>
        <div class="table-wrap"><table class="stats">
          <thead><tr><th>${t('stats.col_agent')}</th><th class="num">${t('stats.col_calls')}</th><th class="num">${t('stats.col_errors')}</th><th class="num">${t('stats.col_requests')}</th><th>${t('stats.col_last')}</th></tr></thead>
          <tbody>${agentIds.map((id) => {
            const c = byAgentCalls.get(id) ?? { calls: 0, errors: 0, last_at: 0 };
            const q = byAgentReq.get(id) ?? { total: 0, approved: 0, denied: 0 };
            return html`<tr>
              <td><a href="/stats?d=${days}&agent=${enc(id)}">${agentName(id)}</a></td>
              <td class="num"><span class="bar-cell">${bar(c.calls, maxAgent)}${num(c.calls)}</span></td>
              <td class="num">${num(c.errors)}</td>
              <td class="num" title="${t('stats.req_title', { approved: q.approved, denied: q.denied })}">${num(q.total)}</td>
              <td class="muted">${c.last_at ? fmtDate(c.last_at) : '—'}</td>
            </tr>`;
          })}</tbody>
        </table></div>
      </section>`}

      <section>
        <h2>${t('stats.by_key')}</h2>
        ${credIds.length ? html`<div class="table-wrap"><table class="stats">
          <thead><tr><th>${t('stats.col_key')}</th><th class="num">${t('stats.col_calls')}</th><th class="num">${t('stats.col_errors')}</th><th>${t('stats.col_last')}</th></tr></thead>
          <tbody>${credIds.map((id) => {
            const c = byCred.get(id);
            return html`<tr>
              <td><span class="key-cell"><img class="ico-sm" src="/public/icons/${enc(credIcon(id))}.svg" alt="" width="20" height="20">${credName(id)}</span></td>
              <td class="num"><span class="bar-cell">${bar(c.calls, maxCred)}${num(c.calls)}</span></td>
              <td class="num">${num(c.errors)}</td>
              <td class="muted">${c.last_at ? fmtDate(c.last_at) : '—'}</td>
            </tr>`;
          })}</tbody>
        </table></div>` : html`<p class="muted">${t('stats.no_key_calls')}</p>`}
      </section>

      <section>
        <h2>${t('stats.recent')}</h2>
        ${recent.length ? html`<div class="table-wrap"><table class="stats calls">
          <thead><tr><th>${t('stats.col_when')}</th>${agentId ? '' : html`<th>${t('stats.col_agent')}</th>`}<th>${t('stats.col_key')}</th><th>${t('stats.col_request')}</th><th class="num">${t('stats.col_status')}</th><th class="num">${t('stats.col_ms')}</th></tr></thead>
          <tbody>${recent.map((r) => html`<tr>
            <td class="muted">${fmtDate(r.at)}</td>
            ${agentId ? '' : html`<td>${agentName(r.agent_id)}</td>`}
            <td>${credName(r.credential_id)}</td>
            <td><code>${r.target}</code></td>
            <td class="num"><span class="code ${Number(r.status) >= 200 && Number(r.status) < 400 ? 'code-ok' : 'code-err'}">${statusText(r.status)}</span></td>
            <td class="num muted">${r.ms == null ? '' : num(r.ms)}</td>
          </tr>`)}</tbody>
        </table></div>
        <p class="hint">${t('stats.recent_hint', { n: recent.length, calls: plural(recent.length, [t('unit.call.one'), t('unit.call.few'), t('unit.call.many')]) })}</p>` : html`<p class="muted">${t('stats.no_calls')}</p>`}
      </section>
    ` : html`<div class="empty"><p>${t('stats.empty')}</p></div>`}
  `, { csrf });
}
