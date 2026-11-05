// Заявки агентов и решения владельца (ТЗ §7, §8)
import crypto from 'node:crypto';
import { t, createI18n } from '../i18n.js';

// Причины отказа уходят агенту (API, MCP): всегда английские, не зависят от языка интерфейса владельца.
const agentT = createI18n('en').t;

const PENDING_TTL = 600;
const MAX_PENDING_PAIR = 3; // ожидающих на пару агент+ключ
const MAX_PENDING_AGENT = 10; // ожидающих на агента
const LIMITS = { ttl: [300, 86400], calls: [1, 100000] };

function clamp(v, [lo, hi], max) { const n = Number(v); if (!Number.isFinite(n)) return Math.min(max, hi); return Math.max(lo, Math.min(n, hi, max)); }

/** Окно действия ключа: days 1..7 (пн=1), from/to 'HH:MM' в tz */
export function inWindow(window, tz, now = new Date()) {
  if (!window || !window.days?.length) return true;
  const fmt = new Intl.DateTimeFormat('en-US', { timeZone: tz || 'UTC', weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
  const parts = Object.fromEntries(fmt.formatToParts(now).map((p) => [p.type, p.value]));
  const dayMap = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 };
  const day = dayMap[parts.weekday] ?? 0;
  const hm = `${parts.hour}:${parts.minute}`.replace(/^24/, '00');
  const from = window.from || '00:00', to = window.to || '23:59';
  if (from <= to) return window.days.includes(day) && hm >= from && hm <= to;
  // Окно через полночь (пн 22:00–06:00): часть после полуночи относится к дню начала окна (П-12)
  const prev = day === 1 ? 7 : day - 1;
  return (hm >= from && window.days.includes(day)) || (hm <= to && window.days.includes(prev));
}

export function createRequestService({ repo, grants, notify, tz, verifyTotp, logger }) {
  const credentialUsable = (cred) => {
    if (!cred) return agentT('requests.err.key_missing');
    if (cred.expires_at && cred.expires_at <= Math.floor(Date.now() / 1000)) return agentT('requests.err.key_expired');
    if (cred.mode === 'deny') return agentT('requests.err.key_denied');
    if (!inWindow(cred.window, tz)) return agentT('requests.err.key_window');
    return null;
  };

  const svc = {
    credentialUsable,

    submit({ agent, credential, ttl, calls, reason, via = 'rest' }) {
      if (!agent?.enabled) return { kind: 'denied', reason: agentT('requests.err.agent_off') };
      const problem = credentialUsable(credential);
      if (problem) return { kind: 'denied', reason: problem };
      const now = Math.floor(Date.now() / 1000);
      const req = {
        id: crypto.randomBytes(12).toString('base64url'),
        agent_id: agent.id, credential_id: credential.id,
        ttl: clamp(ttl, LIMITS.ttl, credential.max_ttl),
        calls: clamp(calls, LIMITS.calls, credential.max_calls),
        reason: String(reason || '').replace(/[\r\n\t]+/g, ' ').slice(0, 200),
        expires_at: now + PENDING_TTL,
      };
      // «Без вопросов на время»: после always_until ключ работает как 'ask', даже если цикл ещё не сбросил режим.
      const auto = credential.mode === 'always' && (credential.always_until == null || credential.always_until > now);
      // Автопропуск не переживает режим «без вопросов»: срок не дольше always_until.
      if (auto && credential.always_until != null) req.ttl = Math.min(req.ttl, credential.always_until - now);
      // Потолок ожидающих заявок (Н-6): автопропуск заявку в ожидании не создаёт, его не считаем
      if (!auto) {
        const n = repo.countPendingRequests(agent.id, credential.id);
        if (n.pair >= MAX_PENDING_PAIR || n.agent >= MAX_PENDING_AGENT) return { kind: 'too_many_pending' };
      }
      repo.createRequest(req);
      repo.touchAgent(agent.id);
      if (auto) {
        const { grant, token } = grants.issue(req, credential, (g) => repo.approveRequest(req.id, 'auto', g));
        repo.audit(`agent:${agent.id}`, 'grant.auto', grant.id, { credential: credential.id, ttl: req.ttl, calls: req.calls, via });
        notify.grantAuto(grant, credential, agent).catch((e) => logger.warn({ err: e.message }, 'notify.grantAuto'));
        return { kind: 'granted', grant, token };
      }
      repo.audit(`agent:${agent.id}`, 'request.create', req.id, { credential: credential.id, ttl: req.ttl, calls: req.calls, via });
      notify.requestCreated(repo.getRequest(req.id), credential, agent).catch((e) => logger.warn({ err: e.message }, 'notify.requestCreated'));
      return { kind: 'pending', requestId: req.id };
    },

    /**
     * totp — код для approval *_code. Проверяется здесь при любом способе одобрения (бот, сайт):
     * без кода или без проверяющей функции одобрить такую заявку нельзя (П-5).
     */
    async decide({ requestId, approve, via, totp }) {
      const req = repo.getRequest(requestId);
      if (!req || req.status !== 'pending') return { ok: false, error: 'not_pending' };
      if (req.expires_at <= Math.floor(Date.now() / 1000)) { repo.expireRequests(); return { ok: false, error: 'not_pending' }; }
      if (approve) {
        const cred0 = repo.getCredential(req.credential_id);
        if (!cred0) { repo.decideRequest(requestId, 'denied', via); return { ok: false, error: 'unavailable' }; }
        // Ключ переключили на «код на сайте», пока висела кнопка в Telegram: кнопкой одобрять нельзя.
        if (via === 'tg' && cred0.approval === 'web_code') return { ok: false, error: 'use_web' };
        if (cred0.approval.endsWith('_code') && !(verifyTotp && totp && (await verifyTotp(totp)))) return { ok: false, error: 'bad_code' };
        // После await всё перечитываем и дальше работаем синхронно: ключ могли удалить, отвязать или
        // ужесточить, агента — выключить, пока шла проверка кода (П-10, П-5).
        const cred = repo.getCredential(req.credential_id);
        const agent = repo.getAgent(req.agent_id);
        if (!cred || !agent?.enabled || !repo.agentCanUse(agent.id, cred.id) || credentialUsable(cred)) {
          repo.decideRequest(requestId, 'denied', via); return { ok: false, error: 'unavailable' };
        }
        // Лимиты заявки — не больше текущих максимумов ключа: их могли уменьшить, пока заявка ждала.
        const capped = { ...req, ttl: Math.min(req.ttl, cred.max_ttl), calls: Math.min(req.calls, cred.max_calls) };
        const issued = grants.issue(capped, cred, (g) => repo.approveRequest(requestId, via, g));
        if (!issued) return { ok: false, error: 'not_pending' };
        const { grant } = issued;
        repo.audit('owner', 'request.approve', requestId, { via, grant: grant.id });
        notify.requestDecided(repo.getRequest(requestId), 'approved').catch(() => {});
        return { ok: true, grant };
      }
      if (!repo.decideRequest(requestId, 'denied', via)) return { ok: false, error: 'not_pending' };
      repo.audit('owner', 'request.deny', requestId, { via });
      notify.requestDecided(repo.getRequest(requestId), 'denied').catch(() => {});
      return { ok: true };
    },

    status(requestId) {
      const req = repo.getRequest(requestId);
      if (!req) return null;
      if (req.status === 'approved') {
        const grant = repo.listActiveGrants().find((g) => g.request_id === req.id) || null;
        return { status: 'approved', grant };
      }
      return { status: req.status };
    },

    expireLoop() {
      const timer = setInterval(() => {
        try {
          const before = repo.listPending();
          const n = repo.expireRequests();
          if (n) for (const r of before) { const now = repo.getRequest(r.id); if (now.status === 'expired') notify.requestDecided(now, 'expired').catch(() => {}); }
        } catch (e) { logger.error({ err: e.message }, 'expireRequests'); }
        try {
          for (const c of repo.endExpiredAlways()) {
            repo.audit('system', 'credential.always_end', c.id, null);
            notify.info(t('notify.always_ended', { provider: c.provider, label: c.label }), 'key.expired').catch(() => {});
          }
        } catch (e) { logger.error({ err: e.message }, 'endExpiredAlways'); }
      }, 10_000);
      timer.unref();
      return timer;
    },
  };
  return svc;
}
