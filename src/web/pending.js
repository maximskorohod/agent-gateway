// Черновики действий при уходе на ввод кода 2FA (П-19): форма не теряется, после кода владелец видит «было → стало»
// и подтверждает отдельным POST. Контракт: docs/contracts/drafts-team-auth.md, раздел «Модуль src/web/pending.js».
// В базе лежат только поля allowlist типа действия; поле с именем секрета в теле — ошибка программиста.
import crypto from 'node:crypto';
import { ACTIONS, runAction } from './actions.js';
import { OWNER_USER_ID } from '../db/repo.js';

export const PENDING_TTL = 300;

const SECRET_NAME = /key|secret|password|token|code/i;
const MAX_VALUE = 20000;
const MAX_ITEMS = 600;

/** Внутренний сигнал: откатить транзакцию (запись черновика вернётся) и отдать результат вызывающему. */
class Abort extends Error {
  constructor(result) { super('pending abort'); this.result = result; }
}

const defOf = (type) => (Object.hasOwn(ACTIONS, type) ? ACTIONS[type] : null);
const allows = (field, name) => (typeof field === 'string' ? field === name : field.test(name));

/** Срезает тело до allowlist типа. Имя вида key|secret|password|token|code вне allowlist — assert (значение в сообщение не попадает). */
export function pickBody(def, body) {
  const out = {};
  for (const [name, v] of Object.entries(body || {})) {
    // поля-шаблоны (ent_<id>) — имена типов данных каталога, не секреты
    const dynamic = def.fields.some((f) => f instanceof RegExp && f.test(name));
    if (!dynamic && SECRET_NAME.test(name)) throw new Error(`pending: secret-like field "${name}" in body of ${def.type}`);
    if (!def.fields.some((f) => allows(f, name))) continue;
    if (typeof v === 'string') out[name] = v.slice(0, MAX_VALUE);
    else if (Array.isArray(v)) out[name] = v.filter((x) => typeof x === 'string').slice(0, MAX_ITEMS).map((x) => x.slice(0, MAX_VALUE));
  }
  return out;
}

/**
 * @param {{ repo:object, can?:(user:object|null, perm:string, target:object)=>boolean,
 *   getUser?:(userId:string)=>object|null, now?:()=>number }} deps
 * До появления users владелец один: getUser читает строку owner (мастер пройден), can пускает только его.
 */
export function createPending({ repo, can, getUser, now }) {
  const nowSec = now ?? (() => Math.floor(Date.now() / 1000));
  const loadUser = getUser ?? ((id) => {
    if (id !== OWNER_USER_ID) return null;
    return repo.getOwner()?.setup_done ? { id, role: 'owner', disabled_at: null } : null;
  });
  const allowed = can ?? ((user) => !!user && !user.disabled_at && user.role === 'owner');
  const permitted = (ctx, def, row) => row.user_id === ctx.userId && allowed(loadUser(ctx.userId), def.perm, { userId: row.user_id, targetId: row.target_id });

  return {
    /** Сохраняет черновик сессии (прежний заменяется, его id мёртв). -> id | null (нет цели или нет прав) */
    save(ctx, type, targetId, body) {
      const def = defOf(type);
      if (!def) throw new Error(`pending: type "${type}" is not allowed`);
      targetId = String(targetId ?? '');
      if (!allowed(loadUser(ctx.userId), def.perm, { userId: ctx.userId, targetId })) return null;
      const clean = pickBody(def, body);
      const version = def.version(ctx, targetId);
      if (version === null) return null;
      const id = crypto.randomBytes(16).toString('base64url');
      repo.inTransaction(() => {
        repo.savePending(ctx.sessionHash, { id, userId: ctx.userId, type, targetId, version, body: clean, expiresAt: nowSec() + PENDING_TTL });
        repo.audit(ctx.userId, 'pending.saved', targetId || null, { type });
      });
      return id;
    },

    /** Состояние не меняет. -> { status:'ok', id, summary, back } | { status:'gone'|'stale'|'forbidden'|'invalid', back?, errors? } */
    view(ctx, id) {
      const row = repo.getPending(ctx.sessionHash, id, nowSec());
      const def = row && defOf(row.type);
      if (!def) return { status: 'gone' };
      if (!permitted(ctx, def, row)) return { status: 'forbidden' };
      const back = def.back(row.target_id);
      if (def.version(ctx, row.target_id) !== row.version) return { status: 'stale', back };
      const { input, errors } = def.parse(ctx, row.target_id, row.body);
      if (errors.length) return { status: 'invalid', errors, back };
      return { status: 'ok', id, summary: def.summary(ctx, row.target_id, input), back };
    },

    /**
     * Применяет черновик одной транзакцией: запись удаляется тем же коммитом, что и изменение (повтор и двойной клик дают 'gone').
     * -> ActionResult | { status:'gone'|'stale'|'forbidden'|'needFresh', back? } | { errors, back }
     * needFresh и ошибки разбора откатывают транзакцию: запись остаётся до срока. Исключение действия откатывает всё.
     */
    apply(ctx, id) {
      try {
        return repo.inTransaction(() => {
          const row = repo.consumePending(ctx.sessionHash, id, nowSec());
          const def = row && defOf(row.type);
          if (!def) return { status: 'gone' };
          // запись остаётся удалённой и при forbidden, и при stale: транзакция завершается штатно
          if (!permitted(ctx, def, row)) return { status: 'forbidden' };
          const back = def.back(row.target_id);
          if (def.version(ctx, row.target_id) !== row.version) {
            repo.audit(ctx.userId, 'pending.stale', row.target_id || null, { type: row.type });
            return { status: 'stale', back };
          }
          if (!ctx.hasRecentTotp) throw new Abort({ status: 'needFresh', back });
          // разбор заново (каталог и правила могли измениться), затем то же исполнение, что у прямого вызова
          const r = runAction(ctx, row.type, row.target_id, row.body, { fromDraft: true });
          if (r.errors) throw new Abort({ errors: r.errors, back: r.back });
          if (r.needFresh) throw new Abort({ status: 'needFresh', back });
          repo.audit(ctx.userId, 'pending.applied', row.target_id || null, { type: row.type });
          return r;
        });
      } catch (e) {
        if (e instanceof Abort) return e.result;
        throw e;
      }
    },

    /** Отмена: удаляет черновик сессии. -> { status:'ok', back } | { status:'gone' } */
    cancel(ctx, id) {
      return repo.inTransaction(() => {
        const row = repo.getPending(ctx.sessionHash, id, nowSec());
        if (!row) return { status: 'gone' };
        repo.deletePending(ctx.sessionHash);
        repo.audit(ctx.userId, 'pending.cancelled', row.target_id || null, { type: row.type });
        return { status: 'ok', back: defOf(row.type)?.back(row.target_id) ?? '/' };
      });
    },
  };
}
