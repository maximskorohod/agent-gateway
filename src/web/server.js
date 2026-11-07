// Сайт владельца (ТЗ §5, §6, §7). Все маршруты здесь; шаблоны — views/.
import crypto from 'node:crypto';
import path from 'node:path';
import fastifyCookie from '@fastify/cookie';
import fastifyFormbody from '@fastify/formbody';
import fastifyStatic from '@fastify/static';
import { sessionPlugin } from '../auth/session.js';
import { OWNER_USER_ID } from '../db/repo.js';
import { csrfPlugin } from './csrf.js';
import { clientKey } from './client-key.js';
import { parsePolicy, sensitiveNeedsConfirm } from './policy.js';
import { runAction } from './actions.js';
import { createPending } from './pending.js';
import { onboardingState, needsWelcome, isKind } from './onboarding.js';
import * as totp from '../auth/totp.js'; // только QR/otpauth для показа; проверки кодов и паролей — в auth/provider.js
import { makeLink, consumeLink, makeShortCode, sha256hex } from '../auth/links.js';
import { createLimiter, createLockout } from '../core/ratelimit.js';
import { buildInjection, validateKeyFormat } from '../catalog.js';
import { defaultFilterFor, normalizeFilter, protectionOf, filterLine } from '../core/filter.js';
import * as V from './views/index.js';
import { t } from '../i18n.js';
import { isInfraError, sendApiError, RETRY_AFTER_SEC } from '../core/infra.js';
import { maskUrl } from '../logger.js';
import { readChannelMeta, writeChannelMeta, checkSlackWebhook, checkSmtp, codeOf } from '../notify.js';
import { DEMO_AGENT_ID, DEMO_CREDENTIAL_ID } from '../demo/reset.js';

const TOTP_RECENT = 300;
const WELCOME_SERVICES = 8; // на шаге онбординга самые частые сервисы, полный список по кнопке
const DEMO_RUNS_MAX = 1000; // столько же, сколько плашек: демо рассчитано на 500 сессий

export async function registerWeb(fastify, ctx) {
  const { repo, vault, catalog, requests, config, logger, notify, tg, auth, keys, proxy } = ctx;
  const caps = auth.capabilities;
  const secure = config.publicUrl.startsWith('https://');

  await fastify.register(fastifyCookie);
  await fastify.register(fastifyFormbody, { bodyLimit: 64 * 1024 });
  await fastify.register(fastifyStatic, { root: path.join(config.root, 'src', 'web', 'public'), prefix: '/public/', decorateReply: false, cacheControl: true, maxAge: '1h' });
  await fastify.register(fastifyStatic, { root: config.iconsDir, prefix: '/public/icons/', decorateReply: false, cacheControl: true, maxAge: '1d' });
  await fastify.register(sessionPlugin, { repo, secure, demo: !!config.demo });
  await fastify.register(csrfPlugin, { secure, repo, publicUrl: config.publicUrl });

  const loginLimiter = createLimiter({ limit: 10, windowSec: 60 });
  const lockout = createLockout({ lockAfter: 5, lockSec: 900 });
  const flashes = new Map();         // sessionId -> {type,text}; без сессии — через query ?e=
  const FLASH_MAX = 1000;

  const now = () => Math.floor(Date.now() / 1000);
  const html = (reply, body, code = 200) => reply.code(code).type('text/html; charset=utf-8').send(body);
  const flash = (req, type, text) => { if (!req.session) return; if (flashes.size >= FLASH_MAX) flashes.delete(flashes.keys().next().value); flashes.set(req.session.idHash, { type, text }); };
  const takeFlash = (req) => { if (!req.session) return null; const f = flashes.get(req.session.idHash); flashes.delete(req.session.idHash); return f || null; };
  const LOGIN_ERRORS = { bad: 'login.error.bad', locked: 'login.error.locked', code: 'login.error.code' };
  const loginError = (e) => (Object.hasOwn(LOGIN_ERRORS, e) ? t(LOGIN_ERRORS[e]) : null);
  const ip = (req) => req.ip;
  // Ключ блокировки: IPv4 — адрес, IPv6 — сеть /64 (общий хелпер с демо-защитой)
  const lockKey = (req) => clientKey(req.ip);
  // Общий потолок ошибок кода на весь сайт: перебор с разных адресов упирается в него.
  // Порог выше блокировки по адресу (5), чтобы чужой перебор не запирал владельца; совпадает с потолком провайдера.
  const CODE_FAILS_MAX = 30;
  const codeFails = [];
  const codeLockedGlobally = () => {
    const edge = Date.now() - 3600_000;
    while (codeFails.length && codeFails[0] < edge) codeFails.shift();
    return codeFails.length >= CODE_FAILS_MAX;
  };
  const telegramConnected = () => !!auth.getUser(OWNER_USER_ID)?.tgChatId && !!tg.current();
  // Маршруты смены пароля и 2FA существуют только если провайдер отдаёт управление данными входа шлюзу
  const needManage = (reply) => (caps.manageCredentials ? false : (html(reply, V.errorPage(404, t('error.page_not_found')), 404), true));
  const safeNext = (n) => (typeof n === 'string' && /^\/[A-Za-z0-9/_?=&.-]*$/.test(n) && !n.startsWith('//') ? n : '/');

  fastify.addHook('onSend', async (req, reply) => {
    reply.header('content-security-policy', "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'");
    // same-origin, не no-referrer: при no-referrer браузер шлёт POST формы с Origin: null и CSRF отклоняет каждую форму
    reply.header('x-frame-options', 'DENY'); reply.header('referrer-policy', 'same-origin'); reply.header('x-content-type-options', 'nosniff');
    if (!req.url.startsWith('/public/')) reply.header('cache-control', 'no-store');
  });

  // Ошибка кода на сайте: блокировка по адресу и по сессии + общий потолок на час.
  function codeFailed(req, sKey) {
    repo.audit('owner', 'totp.fail', ip(req), null);
    const l1 = lockout.fail(lockKey(req)); const l2 = lockout.fail(sKey);
    codeFails.push(Date.now());
    if (codeLockedGlobally()) notify.info(t('notify.totp_locked_hour', { n: CODE_FAILS_MAX, ip: ip(req) })).catch(() => {});
    else if (l1 || l2) notify.info(t('notify.totp_locked', { ip: ip(req) })).catch(() => {});
  }
  // Код для одобрения заявки (tg_code / web_code, requests.decide). Счётчик общий для бота и сайта
  // и не сбрасывается повторным нажатием кнопки (П-9): 5 ошибок — пауза 15 минут, 10 за час — до конца часа.
  const APPROVE_KEY = '2fa:approve';
  ctx.verifyTotp = async (code) => {
    if (codeLockedGlobally() || lockout.locked(APPROVE_KEY)) return false;
    const r = await auth.verifySecondFactor({ userId: OWNER_USER_ID, code });
    if (r.ok) { lockout.reset(APPROVE_KEY); return true; }
    if (r.reason === 'locked') return false;
    repo.audit('owner', 'totp.fail', 'approve', null);
    codeFails.push(Date.now());
    if (lockout.fail(APPROVE_KEY) || codeLockedGlobally()) notify.info(t('notify.approve_code_locked')).catch(() => {});
    return false;
  };

  // ---- guards
  const setupDone = () => !!repo.getOwner()?.setup_done;
  function requireOwner(req, reply) {
    if (!req.session || req.session.half) { reply.redirect(req.session ? '/totp?next=' + encodeURIComponent(req.url) : '/login'); return false; }
    if (!setupDone()) { reply.redirect('/setup'); return false; }
    return true;
  }
  function requireRecentTotp(req, reply, next) {
    if (req.hasRecentTotp(TOTP_RECENT)) return true;
    reply.redirect('/totp?next=' + encodeURIComponent(next)); return false;
  }

  // ---- действия с черновиком 2FA (П-19): один реестр для прямого вызова и черновика
  const pending = createPending({ repo, now });
  const PENDING_ID = /^[A-Za-z0-9_-]{22}$/;
  const actionCtx = (req) => ({
    userId: req.session.userId, user: { id: req.session.userId, role: 'owner', disabled_at: null }, sessionHash: req.session.idHash,
    hasRecentTotp: req.hasRecentTotp(TOTP_RECENT), repo, catalog, csrf: req.csrf, telegramConnected: telegramConnected(), now, notify, publicUrl: config.publicUrl,
  });
  // Результат действия: html (токен агента — один раз) или редирект с flash.
  function sendResult(req, reply, r) {
    if (r.html) return html(reply, r.html, r.code || 200);
    if (r.flash) flash(req, r.flash.type, r.flash.text);
    return reply.redirect(r.redirect);
  }
  // Прямой вызов: нужен код — тело сохраняется черновиком и пользователь уходит на /totp с возвратом на /pending/<id>.
  function runDirect(req, reply, type, targetId, body) {
    const ctx = actionCtx(req);
    const r = runAction(ctx, type, targetId, body);
    if (r.errors) { flash(req, 'error', r.errors.join('; ')); return reply.redirect(r.back); }
    if (r.needFresh) {
      const id = pending.save(ctx, type, targetId, body);
      return reply.redirect(id ? '/totp?next=/pending/' + id : '/totp?next=' + encodeURIComponent(r.back));
    }
    return sendResult(req, reply, r);
  }
  // Исходы view/apply/cancel, кроме успеха: сообщение и возврат на страницу цели.
  function pendingOutcome(req, reply, r, id) {
    if (r.status === 'needFresh') return reply.redirect('/totp?next=/pending/' + id);
    if (r.status === 'forbidden') return html(reply, V.errorPage(403, t('error.forbidden')), 403);
    if (r.errors) flash(req, 'error', r.errors.join('; '));
    else flash(req, 'error', t(r.status === 'stale' ? 'flash.draft_stale' : 'flash.draft_gone'));
    return reply.redirect(r.back || '/');
  }
  // Ключи привязки агента из формы -> тело черновика { all:'1'|'0', ids[] } (поля keys_all/keys в черновик не идут)
  const bindingBody = (b) => { const k = keysFromBody(b); return { all: k.all ? '1' : '0', ids: k.ids }; };

  // ---- healthz
  fastify.get('/healthz', async () => ({ ok: true }));

  // ---- мастер первого запуска
  fastify.get('/setup/:code', async (req, reply) => {
    if (!consumeLink(repo, req.params.code, 'setup')) return html(reply, V.errorPage(404, t('error.link_invalid')), 404);
    reply.startSession(req); req.markTotp(); // мастер: доказательство — доступ к консоли сервера
    return reply.redirect('/setup');
  });
  fastify.get('/setup', async (req, reply) => {
    if (!req.session) return reply.redirect('/login');
    if (setupDone()) return reply.redirect('/');
    const o = repo.getOwner() || {};
    const step = !o.password_hash ? 1 : !o.totp_enabled ? 2 : 3;
    const data = {};
    // Перезагрузка на экране кодов не должна терять коды: пока владелец не нажал «Дальше», показываем их снова
    const unsaved = step === 3 && !repo.getMeta('setup_codes_saved') ? repo.getMeta('setup_backup_codes') : null;
    if (unsaved) return html(reply, V.setup({ csrf: req.csrf, step: 2, data: { backupCodes: JSON.parse(unsaved), downloadHref: '/setup/backup-codes.txt' } }));
    if (step === 2) {
      let secret = repo.getMeta('setup_totp_secret');
      if (!secret) { secret = (await auth.beginSecondFactorEnrollment(req.session.userId)).secret; repo.setMeta('setup_totp_secret', secret); }
      data.secret = secret; data.qrSvg = await totp.qrSvg(totp.otpauthUrl(secret, new URL(config.publicUrl).host));
    }
    if (step === 3) { data.tgCode = repo.getMeta('setup_tg_code') || null; data.botUsername = tg.current() ? await tg.current().getUsername() : null; }
    return html(reply, V.setup({ csrf: req.csrf, step, data, error: takeFlash(req)?.text, flash: null }));
  });
  fastify.post('/setup', async (req, reply) => {
    if (!req.session || setupDone()) return reply.redirect('/');
    const b = req.body; const step = String(b.step || '');
    const o = repo.getOwner() || {};
    if (step === '1') {
      const { password, password_repeat } = b;
      if (typeof password !== 'string' || password.length < 12) { flash(req, 'error', t('setup.err_password_short')); return reply.redirect('/setup'); }
      if (password !== password_repeat) { flash(req, 'error', t('setup.err_password_mismatch')); return reply.redirect('/setup'); }
      await auth.setPassword(req.session.userId, password);
      repo.audit('owner', 'setup.password', null, null);
      return reply.redirect('/setup');
    }
    if (step === '2') {
      const secret = repo.getMeta('setup_totp_secret');
      const done = secret ? await auth.confirmSecondFactorEnrollment(req.session.userId, secret, String(b.code || '').trim()) : { ok: false };
      if (!done.ok) { flash(req, 'error', t('setup.err_bad_code')); return reply.redirect('/setup'); }
      const codes = done.backupCodes;
      repo.setMeta('setup_backup_codes', JSON.stringify(codes));
      repo.setMeta('setup_totp_secret', '');
      req.markTotp();
      repo.audit('owner', 'setup.totp', null, null);
      return html(reply, V.setup({ csrf: req.csrf, step: 2, data: { backupCodes: codes, downloadHref: '/setup/backup-codes.txt' } }));
    }
    if (step === '3') {
      if (!o.password_hash || !o.totp_enabled) return reply.redirect('/setup');
      const mode = String(b.mode || '');
      if (mode === 'telegram') {
        const r = await connectTelegram(req, String(b.token || ''));
        if (r.error) flash(req, 'error', r.error);
        return reply.redirect('/setup');
      }
      if (mode === 'check') {
        if (auth.getUser(req.session.userId)?.tgChatId) { repo.setMeta('setup_tg_code', ''); repo.setMeta('setup_backup_codes', ''); repo.setSetupDone(); repo.setMeta('onboarding_pending', '1'); repo.audit('owner', 'setup.done', null, { telegram: true }); return reply.redirect('/welcome'); }
        renewTgCode();
        flash(req, 'error', t('flash.bot_no_start')); return reply.redirect('/setup');
      }
      if (mode === 'slack') {
        if (!requireRecentTotp(req, reply, '/setup')) return reply;
        const r = await connectSlack(req.body.webhook);
        if (r.error) { flash(req, 'error', r.error); return reply.redirect('/setup'); }
        repo.setMeta('setup_backup_codes', ''); repo.setSetupDone(); repo.setMeta('onboarding_pending', '1'); repo.audit('owner', 'setup.done', null, { slack: true });
        flash(req, 'ok', t('flash.slack_connected'));
        return reply.redirect('/welcome');
      }
      if (mode === 'skip') { repo.setMeta('setup_backup_codes', ''); repo.setSetupDone(); repo.setMeta('onboarding_pending', '1'); repo.audit('owner', 'setup.done', null, { telegram: false }); return reply.redirect('/welcome'); }
      // «Дальше» после резервных кодов
      repo.setMeta('setup_codes_saved', '1');
      return reply.redirect('/setup');
    }
    return reply.redirect('/setup');
  });
  fastify.get('/setup/backup-codes.txt', async (req, reply) => {
    if (!req.session) return reply.redirect('/login');
    const codes = repo.getMeta('setup_backup_codes'); if (!codes) return reply.code(404).send('');
    return reply.type('text/plain; charset=utf-8').header('content-disposition', 'attachment; filename="backup-codes.txt"').send(JSON.parse(codes).join('\n') + '\n');
  });

  async function connectTelegram(req, token) {
    token = token.trim();
    if (!/^\d+:[A-Za-z0-9_-]{35}$/.test(token)) return { error: t('error.tg_token_format') };
    try {
      // порядок: проверка нового токена (getMe) -> запись в сейф -> перезапуск бота; опечатка не затирает рабочий токен
      await tg.check(token);
      await vault.put('sys/tg_bot', token);
      const bot = await tg.restart(token);
      const code = makeShortCode(repo, 'tg_link', 900);
      repo.setMeta('setup_tg_code', code);
      repo.setTg(null, 'sys/tg_bot');
      repo.audit('owner', 'telegram.token', null, null);
      return { code, username: await bot.getUsername() };
    } catch (e) { logger.warn({ err: e.message }, 'telegram connect'); return { error: t('error.tg_connect_failed') }; }
  }

  // Код живёт 15 минут: без нового кода просроченная ссылка на бота стала бы тупиком, токен вводить заново не нужно
  function renewTgCode() {
    if (repo.getMeta('setup_tg_code')) repo.setMeta('setup_tg_code', makeShortCode(repo, 'tg_link', 900));
  }

  /** Тест канала с общим таймаутом. -> null при успехе, иначе код ошибки без текста (в нём может быть путь вебхука). */
  async function testChannel(id) {
    const ch = notify.channels?.find((c) => c.id === id);
    if (!ch) return 'not_configured';
    let timer;
    try {
      await Promise.race([ch.test(), new Promise((_, rej) => { timer = setTimeout(() => rej(Object.assign(new Error('timeout'), { code: 'timeout' })), 12_000); })]);
      return null;
    } catch (e) {
      const code = codeOf(e);
      logger.error({ channel: id, errCode: code }, 'notify test failed');
      return code;
    } finally { clearTimeout(timer); }
  }

  /**
   * Подключение Slack за один шаг: проверка адреса, тестовое сообщение, включение канала.
   * Не дошло — прежняя настройка возвращается, нерабочий адрес не остаётся в сейфе. Вызывающий обязан проверить свежий код.
   */
  async function connectSlack(raw) {
    const chk = checkSlackWebhook(raw);
    if (!chk.ok) return { error: t(chk.error) };
    const meta = readChannelMeta(repo, 'slack');
    const previous = meta.configured ? await vault.get(NOTIFY_SECRET.slack) : null;
    await vault.put(NOTIFY_SECRET.slack, chk.value);
    const code = await testChannel('slack');
    if (code) {
      if (previous) await vault.put(NOTIFY_SECRET.slack, previous); else await vault.del(NOTIFY_SECRET.slack);
      return { error: t('flash.notify_test_fail', { code }) };
    }
    writeChannelMeta(repo, 'slack', { ...meta, enabled: true, configured: true });
    repo.audit('owner', 'notify.secret', 'slack', null);
    return {};
  }

  // ---- вход
  fastify.get('/login', async (req, reply) => {
    if (req.session && !req.session.half) return reply.redirect('/');
    // Демо (П-20): /login — автовход общего демо-владельца без пароля и 2FA
    if (config.demo) { reply.startSession(req); req.markTotp(); return reply.redirect('/'); }
    // внешний провайдер: форма пароля не показывается, вход — редиректом на него
    if (caps.external) return reply.redirect((await auth.startExternalLogin(req)).redirect);
    return html(reply, V.login({ csrf: req.csrf, error: loginError(req.query.e), locked: lockout.locked(lockKey(req)) }));
  });
  fastify.post('/login', async (req, reply) => {
    if (!caps.password) return html(reply, V.errorPage(404, t('error.page_not_found')), 404);
    if (lockout.locked(lockKey(req)) || !loginLimiter.take(lockKey(req))) return reply.redirect('/login?e=locked');
    const r = await auth.verifyLogin({ login: req.body.login, password: String(req.body.password || ''), ip: lockKey(req) });
    if (!r.ok) {
      // блокировка пользователя — отдельное сообщение; «отключён» неотличим от неверного пароля
      if (r.reason === 'locked') return reply.redirect('/login?e=locked');
      repo.audit('owner', 'login.fail', ip(req), null);
      // распределённый перебор пароля: вход не блокируется (нужен второй фактор), владельцу уходит уведомление
      if (r.alert === 'distributed') notify.info(t('notify.login_distributed', { ip: ip(req) })).catch(() => {});
      if (lockout.fail(lockKey(req))) notify.info(t('notify.login_locked', { ip: ip(req) })).catch(() => {});
      return reply.redirect('/login?e=bad');
    }
    // Счётчик ошибок по адресу не сбрасываем на верный пароль: только после верного кода.
    reply.startSession(req);
    return reply.redirect('/totp?next=/');
  });
  fastify.get('/l/:token', async (req, reply) => {
    if (!consumeLink(repo, req.params.token, 'open')) return html(reply, V.errorPage(404, t('error.link_invalid')), 404);
    reply.startSession(req);
    repo.audit('owner', 'login.link', null, null);
    return reply.redirect('/totp?next=/');
  });
  fastify.get('/totp', async (req, reply) => {
    if (!req.session) return reply.redirect('/login');
    const next = safeNext(req.query.next);
    // уход с формы на ввод кода: объясняем, что введённое сохранено черновиком (П-19)
    const action = req.session.half ? t('totp.action_login') : next.startsWith('/pending/') ? t('flash.draft_saved') : t('totp.action_confirm');
    return html(reply, V.totp({ csrf: req.csrf, title: req.session.half ? undefined : t('totp.title_confirm'), action, next, error: loginError(req.query.e) }));
  });
  fastify.post('/totp', async (req, reply) => {
    if (!req.session) return reply.redirect('/login');
    const next = safeNext(req.body.next);
    // блокировка и по IP, и по сессии — смена IP не помогает перебору
    const sKey = 's:' + req.session.idHash;
    if (lockout.locked(lockKey(req)) || lockout.locked(sKey) || codeLockedGlobally()) return reply.redirect('/totp?e=locked&next=' + encodeURIComponent(next));
    const r = await auth.verifySecondFactor({ userId: req.session.userId, code: req.body.code, ip: lockKey(req) });
    if (!r.ok) {
      if (r.reason === 'locked') return reply.redirect('/totp?e=locked&next=' + encodeURIComponent(next));
      codeFailed(req, sKey);
      return reply.redirect('/totp?e=code&next=' + encodeURIComponent(next));
    }
    lockout.reset(lockKey(req)); lockout.reset(sKey);
    const wasHalf = !!req.session.half;
    req.markTotp();
    if (wasHalf) { repo.audit('owner', 'login.ok', null, null); notify.security(t('notify.sec.new_session')); }
    return reply.redirect(setupDone() ? next : '/setup');
  });
  fastify.post('/logout', async (req, reply) => { reply.endSession(req); return reply.redirect('/login'); });

  // ---- экран 1
  fastify.get('/', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    // свежая установка: ссылка на онбординг (пропуск, агент или ключ её убирают); сам мастер уводит на /welcome
    const ob = onboardingState(repo, { telegramConnected: telegramConnected() });
    repo.expireRequests();
    const pendingList = repo.listPending();
    const credentials = repo.listCredentials();
    // «Агент увидит: …» для ключа в карточке справа
    const keyLine = credentials[0] ? filterLine(credentials[0].filter, catalog.get(credentials[0].provider)) : null;
    return html(reply, V.keysPage({ csrf: req.csrf, onboarding: needsWelcome(ob) ? ob : null, credentials, pending: pendingList, providers: catalog.list(), keyLine, flash: takeFlash(req), demo: !!config.demo, scenario: config.demo ? demoScenario(req) : null }));
  });

  // ---- демо: сценарий из трёх шагов. Заявка запоминается на сессию посетителя, шаг выводится из её состояния в базе.
  // Пропуск подписан и нигде не хранится: при показе выпускается заново, в журнал попадает только адрес страницы.
  const demoRuns = new Map(); // sessionId -> requestId
  function demoScenario(req) {
    const requestId = demoRuns.get(req.session.idHash);
    const s = requestId ? requests.status(requestId) : null;
    if (s?.status === 'pending') return { step: 2, requestId };
    if (s?.status === 'approved' && s.grant) {
      const { token } = ctx.grants.reissueToken(s.grant);
      return { step: 3, curl: `curl -s ${config.publicUrl}/v1/proxy/demo/deals -H "Authorization: Bearer ${token}"` };
    }
    demoRuns.delete(req.session.idHash); // отклонена, истекла или стёрта сбросом: сценарий с начала
    return { step: 1 };
  }

  // «Simulate agent request» создаёт заявку демо-агента через настоящий requests.submit (лимит 6/мин на IP стоит в demoRouteGuard)
  if (config.demo) {
    fastify.post('/demo/simulate', async (req, reply) => {
      if (!requireOwner(req, reply)) return reply;
      const agent = repo.getAgent(DEMO_AGENT_ID);
      const credential = repo.getCredential(DEMO_CREDENTIAL_ID); // посевной, а не первый в списке: ключи посетителей могут быть удалены
      if (!agent || !credential) { flash(req, 'error', t('demo.no_agent')); return reply.redirect('/'); }
      const submit = () => requests.submit({ agent, credential, ttl: 900, calls: 20, reason: t('demo.simulate_reason'), via: 'demo' });
      let r = submit();
      // Потолок заявок на пару общий: брошенные заявки других посетителей не должны закрывать сценарий, снимаем самую старую
      if (r.kind === 'too_many_pending') {
        const oldest = repo.listPending().find((x) => x.agent_id === agent.id && x.credential_id === credential.id);
        if (oldest) { await requests.decide({ requestId: oldest.id, approve: false, via: 'timeout' }); r = submit(); }
      }
      if (r.kind === 'denied') flash(req, 'error', t('demo.simulate_failed', { reason: r.reason }));
      else if (r.kind === 'too_many_pending') flash(req, 'error', t('demo.simulate_failed', { reason: 'too_many_pending' }));
      else {
        if (demoRuns.size >= DEMO_RUNS_MAX && !demoRuns.has(req.session.idHash)) demoRuns.delete(demoRuns.keys().next().value);
        demoRuns.set(req.session.idHash, r.kind === 'granted' ? r.grant.request_id : r.requestId); // режим ключа «без вопросов» сразу даёт пропуск
        flash(req, 'ok', t('demo.simulated'));
      }
      return reply.redirect('/');
    });

    // Витрина: экраны обычной установки только для показа, данные вымышленные, настоящие обработчики не вызываются.
    fastify.get('/showcase/services/:slug', async (req, reply) => {
      if (!requireOwner(req, reply)) return reply;
      const provider = catalog.showcase().find((p) => p.slug === req.params.slug);
      if (!provider) return html(reply, V.errorPage(404, t('error.no_service'), { nav: true, csrf: req.csrf }), 404);
      return html(reply, V.showcaseService({ provider }));
    });
    fastify.get('/showcase/connect', async (req, reply) => {
      if (!requireOwner(req, reply)) return reply;
      return html(reply, V.showcaseConnect());
    });
    fastify.get('/showcase/connect/:kind', async (req, reply) => {
      if (!requireOwner(req, reply)) return reply;
      if (!isKind(req.params.kind)) return html(reply, V.errorPage(404, t('error.page_not_found'), { nav: true, csrf: req.csrf }), 404);
      return html(reply, V.showcaseAgent({ kind: req.params.kind }));
    });
    fastify.get('/showcase/settings', async (req, reply) => {
      if (!requireOwner(req, reply)) return reply;
      return html(reply, V.showcaseSettings());
    });
  }

  // ---- онбординг «Connect your agent» (ТЗ §5): прогресс выводится из базы; токен только на странице ответа, в адреса не попадает
  fastify.get('/welcome', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const connected = telegramConnected();
    const tgCode = connected ? null : repo.getMeta('setup_tg_code') || null;
    const botUsername = tgCode && tg.current() ? await tg.current().getUsername().catch(() => null) : null;
    return html(reply, V.welcomePage({ csrf: req.csrf, state: onboardingState(repo, { telegramConnected: connected }), providers: catalog.showcase().filter((p) => p.onboarding !== false).slice(0, WELCOME_SERVICES), flash: takeFlash(req), tgCode, botUsername }));
  });
  // Канал заявок прямо из онбординга: после шага человек возвращается сюда, а не теряется в настройках
  fastify.post('/welcome/notify/telegram', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    if (!requireRecentTotp(req, reply, '/welcome')) return reply;
    const r = await connectTelegram(req, String(req.body.token || ''));
    if (r.error) flash(req, 'error', r.error);
    return reply.redirect('/welcome');
  });
  fastify.post('/welcome/notify/check', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    if (auth.getUser(req.session.userId)?.tgChatId) { repo.setMeta('setup_tg_code', ''); flash(req, 'ok', t('flash.tg_connected')); } else { renewTgCode(); flash(req, 'error', t('flash.bot_no_start')); }
    return reply.redirect('/welcome');
  });
  fastify.post('/welcome/notify/slack', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    if (!requireRecentTotp(req, reply, '/welcome')) return reply;
    const r = await connectSlack(req.body.webhook);
    flash(req, r.error ? 'error' : 'ok', r.error ?? t('flash.slack_connected'));
    return reply.redirect('/welcome');
  });
  fastify.post('/welcome/agent/:kind', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    if (!isKind(req.params.kind)) return html(reply, V.errorPage(404, t('error.page_not_found')), 404);
    // создание агента требует свежего кода: до него карточка уходит в черновик (kind входит в тело)
    return runDirect(req, reply, 'agent.create', '', { kind: req.params.kind, all: '1', ids: [] });
  });
  fastify.post('/welcome/skip', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    repo.setMeta('onboarding_skipped', '1');
    return reply.redirect('/');
  });
  fastify.post('/welcome/skip-notify', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    repo.setMeta('onboarding_notify_skipped', '1');
    return reply.redirect('/welcome');
  });
  // Проверка подключения (ТЗ 1.0.2): только владелец, без JS и опроса, обновление переходом по ссылке.
  // В демо маршрут закрыт allowlist-ом (в таблицу demoRouteGuard не добавлен).
  fastify.get('/welcome/check/:id', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const agent = repo.getAgent(req.params.id);
    if (!agent) return html(reply, V.errorPage(404, t('error.page_not_found')), 404);
    return html(reply, V.welcomeCheck({ agent }));
  });

  // ---- ключи
  fastify.get('/keys', async (req, reply) => reply.redirect('/'));
  fastify.get('/keys/new', async (req, reply) => { if (!requireOwner(req, reply)) return reply; return html(reply, V.pickProvider({ csrf: req.csrf, providers: catalog.list(), showcase: config.demo ? catalog.showcase() : null })); });
  fastify.get('/keys/new/:provider', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const provider = catalog.get(req.params.provider); if (!provider) return html(reply, V.errorPage(404, t('error.no_service'), { nav: true, csrf: req.csrf }), 404);
    return html(reply, V.keyForm({ csrf: req.csrf, provider, values: {}, errors: [], telegramConnected: telegramConnected() }));
  });
  fastify.post('/keys/new/:provider', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const provider = catalog.get(req.params.provider); if (!provider) return html(reply, V.errorPage(404, t('error.no_service')), 404);
    const b = req.body;
    const errors = [];
    let built;
    try { built = buildInjection(provider, b); } catch (e) { errors.push(e.message); }
    if (built && provider.fields.includes('key')) { const bad = validateKeyFormat(provider, b.key); if (bad) errors.push(bad); }
    const { policy, errors: perr } = parsePolicy(b, { telegramConnected: telegramConnected() });
    errors.push(...perr);
    if (sensitiveNeedsConfirm(policy, {}, provider, b)) errors.push(t('policy.err.sensitive_confirm'));
    if (policy.mode === 'always' && !req.hasRecentTotp(TOTP_RECENT)) { policy.mode = 'ask'; policy.always_until = null; flash(req, 'ok', t('flash.key_saved_ask')); }
    if (errors.length) return html(reply, V.keyForm({ csrf: req.csrf, provider, values: { ...b, key: '' }, errors, telegramConnected: telegramConnected() }), 400);
    const id = crypto.randomBytes(8).toString('base64url');
    await vault.put(`cred/${id}`, built.secret);
    repo.createCredential({ id, provider: provider.slug, kind: built.kind, host: built.host, injection: built.injection, vault_param: `cred/${id}`, last4: built.last4, ...policy, label: policy.label || provider.name }); // label после ...policy: пустое имя из формы не затирает имя сервиса
    // слой 1 (п. 7.2): у CRM чтение включено сразу; форма с галочками (protect_form) переопределяет умолчание каталога
    let protect = defaultFilterFor(provider);
    if (b.protect_form === '1') {
      const avail = protectionOf(provider);
      const ro = b.read_only === '1' && avail.readOnly;
      const mk = b.mask === '1' && avail.mask;
      protect = ro || mk ? { ...normalizeFilter(null, provider), ...(ro && { readOnly: true }), ...(mk && { mask: true }) } : null;
    }
    if (protect) repo.updateCredentialFilter(id, protect);
    repo.audit('owner', 'credential.create', id, { provider: provider.slug, mode: policy.mode, ...(protect?.readOnly && { read_only: true }), ...(protect?.mask && { mask: true }) });
    if (!flashes.has(req.session.idHash)) flash(req, 'ok', t('flash.key_added', { name: provider.name }));
    // Первый ключ на свежей установке: возвращаем к следующему шагу, ссылка с главной к этому моменту уже исчезла
    const ob = onboardingState(repo, { telegramConnected: telegramConnected() });
    return reply.redirect(ob.pending && !ob.skipped && ob.count < 3 ? '/welcome' : '/');
  });
  fastify.get('/keys/:id', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const cred = repo.getCredential(req.params.id); if (!cred) return html(reply, V.errorPage(404, t('error.key_not_found'), { nav: true, csrf: req.csrf }), 404);
    repo.expireRequests();
    return html(reply, V.keyDetail({ csrf: req.csrf, cred, provider: catalog.get(cred.provider), telegramConnected: telegramConnected(), flash: takeFlash(req), credentials: repo.listCredentials(), pending: repo.listPending(), providers: catalog.list() }));
  });
  fastify.post('/keys/:id/policy', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    return runDirect(req, reply, 'key.policy', req.params.id, req.body);
  });
  fastify.post('/keys/:id/filter', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    return runDirect(req, reply, 'key.filter', req.params.id, req.body);
  });
  // «Проверить на одном вызове» (ТЗ §9.3): один чтение-вызов владельца, в ответе только имена полей. CSRF проверяет плагин
  fastify.post('/keys/:id/preview', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const cred = repo.getCredential(req.params.id); if (!cred) return html(reply, V.errorPage(404, t('error.key_not_found')), 404);
    const result = await proxy.preview(cred.id); // сбой сейфа/базы — исключение, обработчик корня отдаёт 503 (П-30)
    return html(reply, V.keyDetail({ csrf: req.csrf, cred, provider: catalog.get(cred.provider), telegramConnected: telegramConnected(), preview: result }));
  });
  fastify.post('/keys/:id/replace', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const cred = repo.getCredential(req.params.id); if (!cred) return html(reply, V.errorPage(404, t('error.key_not_found')), 404);
    const provider = catalog.get(cred.provider);
    if (!provider) { flash(req, 'error', t('error.no_service')); return reply.redirect(`/keys/${cred.id}`); }
    try {
      // Ввод владельца как есть (П-25); у «Другого» адрес и заголовок — из сохранённого ключа.
      const input = provider.builder === 'other'
        ? { ...req.body, host: `https://${cred.host}`, header: cred.injection?.name }
        : { ...req.body };
      const built = buildInjection(provider, input);
      const bad = provider.fields.includes('key') ? validateKeyFormat(provider, req.body.key) : null;
      if (bad) throw new Error(bad);
      // Новый секрет не должен уйти на другой адрес, чем у ключа (другой портал/аккаунт).
      if (built.host !== cred.host) throw new Error(t('catalog.err.replace_host', { host: built.host }));
      await vault.put(`cred/${cred.id}`, built.secret);
      repo.updateCredentialSecretMeta(cred.id, { last4: built.last4, vault_param: `cred/${cred.id}` });
      repo.audit('owner', 'credential.replace', cred.id, null);
      flash(req, 'ok', t('flash.key_replaced'));
    } catch (e) { if (isInfraError(e)) throw e; flash(req, 'error', e.message); } // сбой сейфа — страница 503, не текст ошибки (П-30)
    return reply.redirect(`/keys/${cred.id}`);
  });
  fastify.post('/keys/:id/delete', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const cred = repo.getCredential(req.params.id); if (!cred) return html(reply, V.errorPage(404, t('error.key_not_found')), 404);
    if (!requireRecentTotp(req, reply, `/keys/${cred.id}`)) return reply;
    // Сначала сейф, потом база: при сбое сейфа запись остаётся (повторное удаление работает), сироты в сейфе нет.
    await vault.del(`cred/${cred.id}`);
    repo.softDeleteCredential(cred.id);
    repo.audit('owner', 'credential.delete', cred.id, { provider: cred.provider });
    flash(req, 'ok', t('flash.key_deleted'));
    return reply.redirect('/');
  });

  // ---- заявки
  async function decideWeb(req, reply, approve) {
    if (!requireOwner(req, reply)) return reply;
    const r = repo.getRequest(req.params.id); const cred = r && repo.getCredential(r.credential_id);
    if (!r || !cred) { flash(req, 'error', t('flash.request_not_found')); return reply.redirect('/'); }
    // Заявку с кодом одобряет только код, введённый для этой заявки: свежий вход не считается (П-5)
    if (approve && cred.approval.endsWith('_code')) return reply.redirect(`/requests/${encodeURIComponent(r.id)}/approve-confirm`);
    const res = await requests.decide({ requestId: r.id, approve, via: 'web' });
    flash(req, res.ok ? 'ok' : 'error', res.ok ? (approve ? t('flash.access_approved') : t('flash.request_denied')) : t('flash.request_inactive'));
    return reply.redirect('/');
  }
  // Экран заявки: GET только показывает, решение принимают POST ниже. Строку берём из listPending: там имя агента и подпись ключа
  fastify.get('/requests/:id', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    repo.expireRequests();
    const r = repo.listPending().find((x) => x.id === req.params.id);
    if (!r) { flash(req, 'error', t('flash.request_inactive')); return reply.redirect('/'); }
    const c = repo.getCredential(r.credential_id);
    return html(reply, V.requestPage({ csrf: req.csrf, request: r, providers: catalog.list(), filterLine: c ? filterLine(c.filter, catalog.get(c.provider)) : null, flash: takeFlash(req) }));
  });
  fastify.post('/requests/:id/approve', (req, reply) => decideWeb(req, reply, true));
  fastify.post('/requests/:id/deny', (req, reply) => decideWeb(req, reply, false));
  // GET только показывает форму кода, решение — POST с CSRF (П-6)
  fastify.get('/requests/:id/approve-confirm', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const r = repo.getRequest(req.params.id);
    if (!r || r.status !== 'pending') { flash(req, 'error', t('flash.request_inactive')); return reply.redirect('/'); }
    // контекст заявки: чьё, к какому ключу, на сколько и сколько вызовов (без секретов)
    const cred = repo.getCredential(r.credential_id);
    const details = [
      [t('totp.d_agent'), repo.getAgent(r.agent_id)?.name ?? '—'],
      [t('totp.d_key'), cred ? V.keyName(cred, catalog.list()) : '—'],
      [t('totp.d_ttl'), V.fmtDuration(r.ttl)],
      [t('totp.d_calls'), String(r.calls)],
    ];
    return html(reply, V.totp({ csrf: req.csrf, title: t('totp.title_approve'), details, action: t('totp.action_approve'), formAction: `/requests/${encodeURIComponent(r.id)}/approve-code`, error: loginError(req.query.e) }));
  });
  fastify.post('/requests/:id/approve-code', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const back = `/requests/${encodeURIComponent(req.params.id)}/approve-confirm`;
    const sKey = 's:' + req.session.idHash;
    if (lockout.locked(lockKey(req)) || lockout.locked(sKey) || codeLockedGlobally()) return reply.redirect(back + '?e=locked');
    const res = await requests.decide({ requestId: req.params.id, approve: true, via: 'web', totp: String(req.body.code || '').trim() });
    // общий счётчик уже увеличен в ctx.verifyTotp; здесь — блокировка по адресу и сессии
    if (res.error === 'bad_code') { lockout.fail(lockKey(req)); lockout.fail(sKey); return reply.redirect(back + '?e=code'); }
    lockout.reset(lockKey(req)); lockout.reset(sKey);
    flash(req, res.ok ? 'ok' : 'error', res.ok ? t('flash.access_approved') : t('flash.request_inactive'));
    return reply.redirect('/');
  });

  // ---- агенты
  // Поля привязки ключей из формы: keys_all=1|0 и keys (одно значение или массив).
  const keysFromBody = (b) => {
    const ids = b.keys === undefined ? [] : (Array.isArray(b.keys) ? b.keys : [b.keys]);
    return { all: String(b.keys_all ?? '1') !== '0', ids: ids.map(String).slice(0, 500) };
  };
  fastify.get('/agents', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const agents = repo.listAgents();
    const bindings = Object.fromEntries(agents.map((a) => [a.id, repo.listAgentCredentials(a.id)]));
    return html(reply, V.agentsPage({ csrf: req.csrf, agents, credentials: repo.listCredentials(), bindings, providers: catalog.list(), flash: takeFlash(req) }));
  });
  fastify.post('/agents', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    // Новый агент — новый токен доступа к ключам: только со свежим кодом (до него форма уходит в черновик).
    return runDirect(req, reply, 'agent.create', '', { name: req.body.name, ...bindingBody(req.body) });
  });
  for (const [verb, enabled] of [['enable', 1], ['disable', 0]]) {
    fastify.post(`/agents/:id/${verb}`, async (req, reply) => {
      if (!requireOwner(req, reply)) return reply;
      const a = repo.getAgent(req.params.id); if (!a) return reply.redirect('/agents');
      // Выключить можно сразу, включить — только со свежим кодом.
      if (enabled && !requireRecentTotp(req, reply, '/agents')) return reply;
      repo.setAgentEnabled(a.id, enabled);
      repo.audit('owner', `agent.${verb}`, a.id, null);
      flash(req, 'ok', enabled ? t('flash.agent_enabled') : t('flash.agent_disabled'));
      return reply.redirect('/agents');
    });
  }
  fastify.post('/agents/:id/keys', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    // Сузить доступ можно сразу, расширить — только со свежим кодом (до него форма уходит в черновик).
    return runDirect(req, reply, 'agent.keys', req.params.id, bindingBody(req.body));
  });
  // ---- черновик 2FA: страница подтверждения «было → стало», применение и отмена (оба POST с CSRF)
  fastify.get('/pending/:id', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const id = req.params.id;
    if (!PENDING_ID.test(id)) return pendingOutcome(req, reply, { status: 'gone' }, id);
    if (!req.hasRecentTotp(TOTP_RECENT)) return reply.redirect('/totp?next=/pending/' + id);
    const v = pending.view(actionCtx(req), id);
    if (v.status !== 'ok') return pendingOutcome(req, reply, v, id);
    return html(reply, V.pendingPage({ csrf: req.csrf, id, summary: v.summary, flash: takeFlash(req) }));
  });
  fastify.post('/pending/:id/apply', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const id = req.params.id;
    if (!PENDING_ID.test(id)) return pendingOutcome(req, reply, { status: 'gone' }, id);
    const r = pending.apply(actionCtx(req), id);
    if (r.status || r.errors) return pendingOutcome(req, reply, r, id);
    return sendResult(req, reply, r);
  });
  fastify.post('/pending/:id/cancel', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const id = req.params.id;
    if (!PENDING_ID.test(id)) return pendingOutcome(req, reply, { status: 'gone' }, id);
    const r = pending.cancel(actionCtx(req), id);
    if (r.status !== 'ok') return pendingOutcome(req, reply, r, id);
    flash(req, 'ok', t('flash.draft_cancelled'));
    return reply.redirect(r.back);
  });
  fastify.post('/agents/:id/delete', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    if (!requireRecentTotp(req, reply, '/agents')) return reply;
    const a = repo.getAgent(req.params.id); if (!a) return reply.redirect('/agents');
    repo.setAgentEnabled(a.id, 0);
    try { repo.deleteAgent(a.id); flash(req, 'ok', t('flash.agent_deleted')); }
    catch { flash(req, 'ok', t('flash.agent_kept')); }
    repo.audit('owner', 'agent.delete', a.id, null);
    return reply.redirect('/agents');
  });

  // ---- настройки
  fastify.get('/settings', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const u = auth.getUser(req.session.userId);
    const data = { csrf: req.csrf, owner: { totp_enabled: !!u?.totpEnabled }, manageCredentials: caps.manageCredentials, sessions: repo.listSessions().map((s) => ({ ...s, current: s.id_hash === req.session.idHash })), telegramConnected: telegramConnected(), botUsername: tg.current() ? await tg.current().getUsername().catch(() => null) : null, tgCode: repo.getMeta('setup_tg_code') || null, flash: takeFlash(req), notify: { slack: readChannelMeta(repo, 'slack'), email: readChannelMeta(repo, 'email') } };
    const codes = caps.manageCredentials ? takeSessionSecret(req, 'backup_codes') : null; if (codes) data.backupCodes = codes;
    const re = caps.manageCredentials ? peekSessionSecret(req, 'reissue') : null; if (re) { data.reissueSecret = re; data.reissueQr = await totp.qrSvg(totp.otpauthUrl(re, new URL(config.publicUrl).host)); }
    return html(reply, V.settingsPage(data));
  });

  // Секреты, которые надо показать владельцу (новый TOTP при перевыпуске, резервные коды), живут 10 минут,
  // зашифрованы и привязаны к сессии, которая их создала: другая сессия их не увидит и не подтвердит (П-7).
  const SESSION_SECRET_TTL = 600;
  const sessionSecretKey = (req, kind) => `pending:${kind}:${req.session.idHash.slice(0, 32)}`;
  function putSessionSecret(req, kind, value) {
    const enc = totp.encryptSecret(JSON.stringify({ v: value, at: Math.floor(Date.now() / 1000) }), keys.totp);
    repo.setMeta(sessionSecretKey(req, kind), enc);
  }
  function peekSessionSecret(req, kind) {
    const raw = repo.getMeta(sessionSecretKey(req, kind)); if (!raw) return null;
    try {
      const { v, at } = JSON.parse(totp.decryptSecret(raw, keys.totp));
      if (Math.floor(Date.now() / 1000) - at <= SESSION_SECRET_TTL) return v;
    } catch { /* повреждённая запись — как истёкшая */ }
    repo.setMeta(sessionSecretKey(req, kind), '');
    return null;
  }
  function takeSessionSecret(req, kind) {
    const v = peekSessionSecret(req, kind);
    if (v !== null) repo.setMeta(sessionSecretKey(req, kind), '');
    return v;
  }
  // Смена пароля или 2FA: остальные сессии закрываются, пропуска агентов не трогаем (Н-4).
  function closeOtherSessions(req) {
    for (const s of repo.listSessions()) if (s.id_hash !== req.session.idHash) repo.deleteSession(s.id_hash);
  }
  fastify.post('/settings/password', async (req, reply) => {
    if (needManage(reply)) return reply;
    if (!requireOwner(req, reply)) return reply;
    if (!requireRecentTotp(req, reply, '/settings')) return reply;
    const user = auth.getUser(req.session.userId);
    const { password_old: old_password, password_new: password, password_repeat: password2 } = req.body;
    // старый пароль проверяет провайдер (с теми же блокировками пользователя, что и вход)
    const chk = user && await auth.verifyLogin({ login: user.login, password: String(old_password || ''), ip: lockKey(req) });
    if (!chk?.ok) { flash(req, 'error', t('flash.pw_old_wrong')); return reply.redirect('/settings'); }
    if (typeof password !== 'string' || password.length < 12 || password !== password2) { flash(req, 'error', t('flash.pw_new_invalid')); return reply.redirect('/settings'); }
    await auth.setPassword(user.id, password); repo.audit('owner', 'password.change', null, null);
    notify.security(t('notify.sec.password_changed'));
    closeOtherSessions(req);
    repo.deletePending(req.session.idHash); // черновик этой сессии тоже не переживает смену пароля (П-19)
    flash(req, 'ok', t('flash.pw_changed')); return reply.redirect('/settings');
  });
  fastify.post('/settings/2fa/reissue', async (req, reply) => {
    if (needManage(reply)) return reply;
    if (!requireOwner(req, reply)) return reply;
    if (!requireRecentTotp(req, reply, '/settings')) return reply;
    putSessionSecret(req, 'reissue', (await auth.beginSecondFactorEnrollment(req.session.userId)).secret);
    flash(req, 'ok', t('flash.2fa_scan'));
    return reply.redirect('/settings');
  });
  fastify.post('/settings/2fa/confirm', async (req, reply) => {
    if (needManage(reply)) return reply;
    if (!requireOwner(req, reply)) return reply;
    // секрет перевыпуска — только у сессии, которая его начала (со свежим кодом), и не дольше 10 минут
    const secret = peekSessionSecret(req, 'reissue');
    const done = secret ? await auth.confirmSecondFactorEnrollment(req.session.userId, secret, String(req.body.code || '').trim()) : { ok: false };
    if (!done.ok) { flash(req, 'error', t('flash.code_wrong')); return reply.redirect('/settings'); }
    takeSessionSecret(req, 'reissue');
    putSessionSecret(req, 'backup_codes', done.backupCodes);
    repo.audit('owner', 'totp.reissue', null, null);
    notify.security(t('notify.sec.2fa_reissued'));
    closeOtherSessions(req);
    repo.deletePending(req.session.idHash);
    flash(req, 'ok', t('flash.2fa_reissued')); return reply.redirect('/settings');
  });
  fastify.post('/settings/2fa/backup-codes', async (req, reply) => {
    if (needManage(reply)) return reply;
    if (!requireOwner(req, reply)) return reply;
    if (!requireRecentTotp(req, reply, '/settings')) return reply;
    putSessionSecret(req, 'backup_codes', await auth.regenerateBackupCodes(req.session.userId));
    repo.audit('owner', 'backup_codes.new', null, null);
    return reply.redirect('/settings');
  });
  fastify.post('/settings/telegram/connect', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    if (!requireRecentTotp(req, reply, '/settings')) return reply;
    const r = await connectTelegram(req, String(req.body.token || ''));
    if (r.error) flash(req, 'error', r.error);
    return reply.redirect('/settings');
  });
  fastify.post('/settings/telegram/check', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    if (auth.getUser(req.session.userId)?.tgChatId) { repo.setMeta('setup_tg_code', ''); flash(req, 'ok', t('flash.tg_connected')); } else { renewTgCode(); flash(req, 'error', t('flash.bot_no_start')); }
    return reply.redirect('/settings');
  });
  fastify.post('/settings/telegram/disconnect', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    if (!requireRecentTotp(req, reply, '/settings')) return reply;
    await tg.stop(); await vault.del('sys/tg_bot'); repo.setTg(null, null); repo.setMeta('setup_tg_code', '');
    // ключи с tg_* подтверждением переводим на сайт
    for (const c of repo.listCredentials()) if (c.approval.startsWith('tg_')) repo.updateCredentialPolicy(c.id, { approval: c.approval === 'tg_code' ? 'web_code' : 'web_button' });
    repo.audit('owner', 'telegram.disconnect', null, null);
    flash(req, 'ok', t('flash.tg_disconnected')); return reply.redirect('/settings');
  });
  // ---- уведомления (Slack, e-mail): секреты — только со свежим кодом и без черновика; галочки — через реестр действий
  const NOTIFY_SECRET = { slack: 'sys/slack_webhook', email: 'sys/smtp' };
  const notifyId = (req, reply) => {
    if (Object.hasOwn(NOTIFY_SECRET, req.params.id)) return req.params.id;
    html(reply, V.errorPage(404, t('error.page_not_found')), 404); return null;
  };
  // ссылка из сообщений: publicUrl + '/requests' ведёт к списку заявок
  fastify.get('/requests', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    return reply.redirect('/');
  });
  fastify.post('/settings/notify/slack/secret', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    if (!requireRecentTotp(req, reply, '/settings')) return reply;
    const chk = checkSlackWebhook(req.body.webhook);
    if (!chk.ok) { flash(req, 'error', t(chk.error)); return reply.redirect('/settings'); }
    await vault.put(NOTIFY_SECRET.slack, chk.value);
    writeChannelMeta(repo, 'slack', { ...readChannelMeta(repo, 'slack'), configured: true });
    repo.audit('owner', 'notify.secret', 'slack', null);
    flash(req, 'ok', t('flash.notify_secret_saved')); return reply.redirect('/settings');
  });
  fastify.post('/settings/notify/email/secret', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    if (!requireRecentTotp(req, reply, '/settings')) return reply;
    const b = req.body;
    const port = Number(b.port);
    const chk = checkSmtp({ host: b.host, port, encryption: port === 465 ? 'tls' : 'starttls', user: b.user, pass: b.pass, from: b.from, to: b.to });
    if (!chk.ok) { flash(req, 'error', t(chk.error)); return reply.redirect('/settings'); }
    await vault.put(NOTIFY_SECRET.email, JSON.stringify(chk.value));
    writeChannelMeta(repo, 'email', { ...readChannelMeta(repo, 'email'), configured: true });
    repo.audit('owner', 'notify.secret', 'email', null);
    flash(req, 'ok', t('flash.notify_secret_saved')); return reply.redirect('/settings');
  });
  fastify.post('/settings/notify/:id/clear', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const id = notifyId(req, reply); if (!id) return reply;
    if (!requireRecentTotp(req, reply, '/settings')) return reply;
    await vault.del(NOTIFY_SECRET[id]);
    writeChannelMeta(repo, id, { ...readChannelMeta(repo, id), enabled: false, configured: false });
    repo.audit('owner', 'notify.clear', id, null);
    flash(req, 'ok', t('flash.notify_cleared')); return reply.redirect('/settings');
  });
  fastify.post('/settings/notify/:id/test', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const id = notifyId(req, reply); if (!id) return reply;
    if (!readChannelMeta(repo, id).configured || !notify.channels?.some((c) => c.id === id)) { flash(req, 'error', t('flash.notify_no_secret')); return reply.redirect('/settings'); }
    const code = await testChannel(id);
    if (code) flash(req, 'error', t('flash.notify_test_fail', { code })); else flash(req, 'ok', t('flash.notify_test_ok'));
    return reply.redirect('/settings');
  });
  fastify.post('/settings/notify/:id', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const id = notifyId(req, reply); if (!id) return reply;
    return runDirect(req, reply, 'notify.channel', id, { enabled: req.body.enabled, events: req.body.events });
  });
  fastify.post('/settings/sessions/revoke', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    repo.audit('owner', 'sessions.logout_all', null, null); reply.endAllSessions(req); return reply.redirect('/login');
  });
  fastify.post('/settings/revoke-all', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    if (!requireRecentTotp(req, reply, '/settings')) return reply;
    const n = repo.revokeAllGrants(); for (const r of repo.listPending()) repo.decideRequest(r.id, 'denied', 'web');
    repo.audit('owner', 'panic', null, { revoked: n });
    notify.security(t('notify.sec.panic'));
    reply.endAllSessions(req); return reply.redirect('/login');
  });
  // ---- запросы (статистика по журналу вызовов и заявкам)
  fastify.get('/stats', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const d = Number(req.query.d);
    const days = V.STATS_PERIODS.some(([p]) => p === d) ? d : 7;
    const agentId = typeof req.query.agent === 'string' && repo.getAgent(req.query.agent) ? req.query.agent : null;
    const keep = (r) => !agentId || r.agent_id === agentId;
    return html(reply, V.statsPage({
      csrf: req.csrf, days, agentId,
      calls: repo.callStats(days).filter(keep),
      requests: repo.requestStats(days).filter(keep),
      recent: repo.listCalls({ days, agentId, limit: 50 }),
      agents: repo.listAgents(),
      credentials: repo.listCredentials(),
      providers: catalog.list(),
    }));
  });
  fastify.get('/audit', async (req, reply) => {
    if (!requireOwner(req, reply)) return reply;
    const before = req.query.before ? Number(req.query.before) : undefined;
    return html(reply, V.auditPage({ csrf: req.csrf, rows: repo.listAudit({ limit: 200, before }).map((r) => ({ ...r, meta: r.meta_json })) }));
  });

  fastify.setNotFoundHandler((req, reply) => {
    if (req.url.startsWith('/v1/')) return reply.code(404).send({ error: 'not_found' });
    // вошедшему владельцу 404 показывается с меню, чтобы было куда пойти
    const inside = !!req.session && !req.session.half && setupDone();
    return html(reply, V.errorPage(404, t('error.page_not_found'), { nav: inside, csrf: req.csrf }), 404);
  });
  fastify.setErrorHandler((err, req, reply) => {
    // Сбой сейфа или базы — всегда 503 с Retry-After, в одном месте (П-30). URL без query: в нём могут быть токены.
    if (req.url.startsWith('/v1/')) return sendApiError(err, req, reply, logger);
    if (isInfraError(err)) {
      logger.error({ err: err.message, url: maskUrl(req.url), code: err.code, src: err.infra }, 'infra error');
      reply.header('retry-after', String(RETRY_AFTER_SEC));
      return html(reply, V.errorPage(503, t('error.unavailable')), 503);
    }
    const status = err.statusCode || 500;
    // Ошибка запроса (например, обход каталога через /public/), а не сбой: иначе любой посетитель засоряет журнал ошибок
    if (status >= 500) logger.error({ err: err.message, url: maskUrl(req.url), code: err.code }, 'unhandled');
    else logger.info({ err: err.message, url: maskUrl(req.url), code: err.code }, 'request error');
    return html(reply, V.errorPage(status, status === 403 ? t('error.forbidden') : t('error.internal')), status);
  });
}
