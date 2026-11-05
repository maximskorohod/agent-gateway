// Уведомления владельцу: каналы Telegram, Slack, e-mail (контракт rest-demo-notify.md, «Уведомления и лист ожидания»).
// Fan-out через Promise.allSettled, у каждого канала свой таймаут; доставка не блокирует заявки агентов.
// Секреты каналов (вебхук Slack, пароль SMTP) живут только в сейфе (sys/slack_webhook, sys/smtp) и не попадают ни в логи, ни в audit, ни в ошибки.
import { Agent, request as undiciRequest } from 'undici';
import { t } from './i18n.js';
import { isValidOwnerHost } from './catalog.js';
import { resolvePublic } from './core/ssrf.js';
import { filterLine } from './core/filter.js';

export const EVENTS = Object.freeze(['request.created', 'request.decided', 'grant.auto', 'key.expired', 'security', 'info']);
export const CHANNEL_IDS = Object.freeze(['telegram', 'slack', 'email']);
/** События по умолчанию (таблица «Какие события куда»). */
export const DEFAULT_EVENTS = Object.freeze({
  telegram: EVENTS,
  slack: EVENTS,
  email: Object.freeze(['key.expired', 'security']),
});

const CHANNEL_TIMEOUT_MS = 10_000;
const REASON_MAX = 300;
const SLACK_HOST = 'hooks.slack.com';
export const SMTP_PORTS = Object.freeze([587, 465]);

const coded = (code) => Object.assign(new Error(code), { code });
/** Одна строка без управляющих, невидимых символов и разделителей строк. */
const flat = (s) => String(s ?? '').replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, ' ').replace(/\s+/g, ' ').trim();
const clip = (s, n) => Array.from(s).slice(0, n).join('');
/** Код сбоя для лога: короткий, без текста сообщения (в нём может оказаться путь вебхука). */
export const codeOf = (e) => (typeof e?.code === 'string' && /^[A-Za-z0-9_.-]{1,40}$/.test(e.code) ? e.code : 'send_failed');

// ---- проверка настроек (вызывается и при сохранении, и перед каждой отправкой)

/** Slack Incoming Webhook: только https://hooks.slack.com:443/services/..., без учётных данных, query и фрагмента. -> {ok, value} | {ok:false, error: ключ i18n} */
export function checkSlackWebhook(raw) {
  const bad = { ok: false, error: 'flash.slack_url_invalid' };
  const s = String(raw ?? '').trim();
  if (!s || s.length > 300) return bad;
  let u;
  try { u = new URL(s); } catch { return bad; }
  if (u.protocol !== 'https:' || u.hostname !== SLACK_HOST || (u.port && u.port !== '443')) return bad;
  if (u.username || u.password || u.search || u.hash || !/^\/services\/[A-Za-z0-9_/-]{1,250}$/.test(u.pathname)) return bad;
  return { ok: true, value: `https://${SLACK_HOST}${u.pathname}` };
}

const EMAIL_RE = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;

/**
 * Настройки SMTP. Шифрование обязательно: 587 + STARTTLS или 465 + implicit TLS, остальное отклоняется (решение 8).
 * Хост: только доменное имя (isValidOwnerHost). -> {ok, value:{host, port, user, pass, from, to[]}} | {ok:false, error: ключ i18n}
 */
export function checkSmtp(c) {
  const fail = (key) => ({ ok: false, error: key });
  const host = String(c?.host ?? '').trim().toLowerCase();
  if (!isValidOwnerHost(host)) return fail('flash.smtp_host');
  const port = Number(c?.port);
  const enc = String(c?.encryption ?? (port === 465 ? 'tls' : 'starttls')).toLowerCase();
  if (enc === 'none' || c?.tls === false || c?.secure === 'none') return fail('flash.smtp_no_tls');
  if (!SMTP_PORTS.includes(port)) return fail('flash.smtp_no_tls');
  if ((port === 587 && enc !== 'starttls') || (port === 465 && enc !== 'tls')) return fail('flash.smtp_no_tls');
  const user = String(c?.user ?? '');
  const pass = String(c?.pass ?? '');
  if (user.length > 200 || pass.length > 200 || /[\r\n\0]/.test(user + pass) || (user && !pass)) return fail('flash.smtp_auth');
  const from = String(c?.from ?? '').trim();
  if (!EMAIL_RE.test(from)) return fail('flash.smtp_from');
  const toRaw = Array.isArray(c?.to) ? c.to : String(c?.to ?? '').split(/[\s,;]+/);
  const to = toRaw.map((x) => String(x).trim()).filter(Boolean);
  if (!to.length || to.length > 5 || !to.every((x) => EMAIL_RE.test(x))) return fail('flash.smtp_to');
  return { ok: true, value: { host, port, user, pass, from, to } };
}

// ---- форматирование

/** Текст для e-mail: только text/plain, CR/LF и прочие управляющие символы из темы убраны. */
export function emailMessage(msg) {
  const subject = clip(flat(`${t('app.name')}: ${msg.title}`), 200);
  const text = [String(msg.text ?? ''), msg.url ? String(msg.url) : ''].filter(Boolean).join('\n\n');
  return { subject, text };
}

/** Экранирование для Slack: & < > (иначе <!channel> и ссылки сработают). */
const slackEsc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export function slackPayload(msg) {
  const lines = [`*${slackEsc(msg.title)}*`, slackEsc(msg.text)];
  if (msg.url) lines.push(slackEsc(msg.url));
  return JSON.stringify({ text: lines.join('\n') });
}

// ---- каналы

/** meta `notify.<id>` -> {enabled, events[], configured}; повреждённая запись = выключено. */
export function readChannelMeta(repo, id) {
  let m = null;
  try { m = JSON.parse(repo.getMeta(`notify.${id}`) || 'null'); } catch { m = null; }
  const events = Array.isArray(m?.events) ? m.events.filter((e) => EVENTS.includes(e)) : [...DEFAULT_EVENTS[id]];
  return { enabled: !!m?.enabled, events, configured: !!m?.configured };
}
export function writeChannelMeta(repo, id, { enabled, events, configured }) {
  repo.setMeta(`notify.${id}`, JSON.stringify({ enabled: !!enabled, events: events.filter((e) => EVENTS.includes(e)), configured: !!configured }));
}

function telegramChannel({ repo, getBot }) {
  return {
    id: 'telegram',
    buttons: true,
    // Telegram включён, пока бот подключён; события можно сузить записью meta notify.telegram
    enabled: () => !!getBot?.(),
    events: () => readChannelMeta(repo, 'telegram').events,
    async send(msg) {
      const b = getBot?.(); if (!b) return;
      if (msg.event === 'request.created' && msg.raw) return b.sendRequest(msg.raw.request, msg.raw.credential, msg.raw.agent);
      if (msg.event === 'request.decided' && msg.raw) return b.editDecided(msg.raw.request, msg.raw.status);
      return b.send(msg.text);
    },
    async test() { const b = getBot?.(); if (!b) throw coded('not_connected'); await b.send(t('notify.test')); },
  };
}

function slackChannel({ repo, vault, test }) {
  async function post(msg) {
    const chk = checkSlackWebhook(await vault.get('sys/slack_webhook'));
    if (!chk.ok) throw coded('not_configured');
    const u = new URL(chk.value);
    const body = slackPayload(msg);
    const opts = { method: 'POST', headers: { 'content-type': 'application/json' }, body, signal: AbortSignal.timeout(CHANNEL_TIMEOUT_MS), headersTimeout: CHANNEL_TIMEOUT_MS, bodyTimeout: CHANNEL_TIMEOUT_MS };
    let agent = null;
    try {
      let res;
      if (test?.slackOrigin) {
        // только тесты: mock-сервер на localhost вместо hooks.slack.com (настройка приходит из buildApp(overrides), не из env)
        res = await undiciRequest(test.slackOrigin + u.pathname, opts);
      } else {
        // соединение идёт к проверенному публичному адресу, SNI и Host остаются hooks.slack.com; редиректы не выполняются
        const ip = await resolvePublic(u.hostname);
        const family = ip.includes(':') ? 6 : 4;
        agent = new Agent({ connect: { timeout: CHANNEL_TIMEOUT_MS, lookup: (_h, o, cb) => (o?.all ? cb(null, [{ address: ip, family }]) : cb(null, ip, family)) } });
        res = await undiciRequest(chk.value, { ...opts, dispatcher: agent });
      }
      await res.body.dump();
      if (res.statusCode < 200 || res.statusCode >= 300) throw coded(`http_${res.statusCode}`);
    } finally {
      if (agent) agent.close().catch(() => {});
    }
  }
  return {
    id: 'slack',
    buttons: false,
    enabled: () => readChannelMeta(repo, 'slack').enabled,
    events: () => readChannelMeta(repo, 'slack').events,
    send: post,
    test: () => post({ event: 'info', title: t('notify.test_title'), text: t('notify.test') }),
  };
}

function emailChannel({ repo, vault, publicUrl, test }) {
  async function mail(msg) {
    let raw = await vault.get('sys/smtp');
    try { raw = JSON.parse(raw); } catch { raw = null; }
    const chk = checkSmtp(raw);
    if (!chk.ok) throw coded('not_configured');
    const c = chk.value;
    // nodemailer подключается лениво: пока канал не включён, модуль не загружается
    const mod = await import('nodemailer');
    const nodemailer = mod.default ?? mod;
    let host; let port = c.port;
    if (test?.smtp) { host = test.smtp.host; port = test.smtp.port; } // только тесты: mock SMTP на localhost
    else host = await resolvePublic(c.host); // проверенный публичный IP; имя хоста идёт в TLS servername
    let ownName = 'localhost';
    try { ownName = new URL(publicUrl).hostname || ownName; } catch { /* оставляем localhost */ }
    const transport = nodemailer.createTransport({
      host, port,
      secure: c.port === 465,
      requireTLS: true,
      name: ownName,
      auth: c.user ? { user: c.user, pass: c.pass } : undefined,
      tls: { servername: c.host, rejectUnauthorized: true, minVersion: 'TLSv1.2' },
      connectionTimeout: CHANNEL_TIMEOUT_MS, greetingTimeout: CHANNEL_TIMEOUT_MS, socketTimeout: CHANNEL_TIMEOUT_MS,
      disableFileAccess: true, disableUrlAccess: true,
    });
    try {
      const { subject, text } = emailMessage(msg);
      await transport.sendMail({ from: c.from, to: c.to, subject, text });
    } finally {
      transport.close();
    }
  }
  return {
    id: 'email',
    buttons: false,
    enabled: () => readChannelMeta(repo, 'email').enabled,
    events: () => readChannelMeta(repo, 'email').events,
    send: mail,
    test: () => mail({ event: 'info', title: t('notify.test_title'), text: t('notify.test') }),
  };
}

/** Каналы по умолчанию: telegram + slack + email из настроек. */
export function createChannels({ repo, getBot, vault, publicUrl, test }) {
  return [telegramChannel({ repo, getBot }), slackChannel({ repo, vault, test }), emailChannel({ repo, vault, publicUrl, test })];
}

// ---- уведомитель

/**
 * @param {{ repo:object, getBot?:()=>object|null, vault:object, logger:object, publicUrl?:string,
 *   channels?:object[], timeoutMs?:number, test?:{slackOrigin?:string, smtp?:{host:string,port:number}} }} deps
 * test приходит только из buildApp(overrides) в тестах и никогда не читается из окружения.
 */
export function createNotifier({ repo, getBot, vault, logger, catalog = null, publicUrl = '', channels, timeoutMs = CHANNEL_TIMEOUT_MS, test = null }) {
  const list = channels ?? createChannels({ repo, getBot, vault, publicUrl, test });
  const inflight = new Set();
  const human = (sec) => (sec % 3600 === 0 ? `${sec / 3600} ${t('unit.h')}` : `${Math.round(sec / 60)} ${t('unit.min')}`);
  const link = () => `${publicUrl}/requests`;

  function withTimeout(ch, msg) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(coded('timeout')), timeoutMs);
      let p;
      try { p = Promise.resolve(ch.send(msg)); } catch (e) { p = Promise.reject(e); }
      p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
    });
  }

  /** Рассылка по каналам; никогда не бросает. В лог идут только id канала и код сбоя. */
  function dispatch(msg) {
    const targets = list.filter((ch) => {
      try { return ch.enabled() && ch.events().includes(msg.event); } catch { return false; }
    });
    const p = Promise.allSettled(targets.map((ch) => withTimeout(ch, msg))).then((results) => {
      results.forEach((r, i) => {
        if (r.status === 'rejected') {
          // поле не «code»: pino-redact логгера закрывает ключ code звёздочками (там коды 2FA)
          try { logger.error({ channel: targets[i].id, errCode: codeOf(r.reason) }, 'notify failed'); } catch { /* логгер не должен ронять рассылку */ }
        }
      });
    });
    inflight.add(p);
    p.finally(() => inflight.delete(p));
    return p;
  }

  const reasonOf = (r) => clip(flat(r), REASON_MAX) || '-';
  const titleKey = (event) => `notify.title.${event.replace('.', '_')}`;

  /** event: 'info' (по умолчанию), 'key.expired' или 'security'. */
  function info(text, event = 'info') {
    const ev = EVENTS.includes(event) ? event : 'info';
    return dispatch({ event: ev, title: t(titleKey(ev)), text: String(text), url: link() });
  }

  return {
    channels: list,
    /** Ждёт доставки всех уже запущенных рассылок (для тестов). */
    async idle() { while (inflight.size) await Promise.allSettled([...inflight]); },
    requestCreated(request, credential, agent) {
      // «Агент увидит: …» из фильтра ключа (п. 7.3); без каталога или при сбое описания строки нет
      let seen = '';
      try { if (catalog && credential) seen = filterLine(credential.filter, catalog.get(credential.provider)); } catch { seen = ''; }
      return dispatch({
        event: 'request.created', title: t(titleKey('request.created')), url: link(),
        text: t('notify.request_created', { agent: flat(agent?.name), provider: credential?.provider, label: flat(credential?.label), ttl: human(request.ttl), calls: request.calls, reason: reasonOf(request.reason) }) + (seen ? `\n${seen}` : ''),
        raw: { request, credential, agent },
      });
    },
    requestDecided(request, status) {
      const cred = repo.getCredential(request.credential_id);
      const agent = repo.getAgent(request.agent_id);
      const line = ['approved', 'denied', 'expired'].includes(status) ? t(`bot.decided.${status}`) : String(status);
      return dispatch({
        event: 'request.decided', title: t(titleKey('request.decided')), url: link(),
        text: t('notify.request_decided', { agent: flat(agent?.name) || '-', provider: cred?.provider || '-', label: flat(cred?.label) || '-', status: line }),
        raw: { request, status },
      });
    },
    grantAuto(grant, credential, agent) {
      return dispatch({
        event: 'grant.auto', title: t(titleKey('grant.auto')), url: link(),
        text: t('notify.grant_auto', { agent: agent.name, provider: credential.provider, label: credential.label, ttl: human(grant.expires_at - grant.created_at), calls: grant.max_calls }),
      });
    },
    info,
    security: (text) => info(text, 'security'),
  };
}
