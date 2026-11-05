// Все запросы к базе. Конструктор получает открытый db (см. db/index.js).
// Все методы синхронные (better-sqlite3). Подготовленные statements создаются один раз в createRepo.
// Время — unixepoch() внутри SQL. Внутри db.transaction никаких await.

import { AUDIT_DDL, AUDIT_TABLE_DDL } from './index.js';

/** better-sqlite3 отдаёт undefined для пустого результата — приводим к null. */
const orNull = (row) => row ?? null;

/** Строка credentials → объект Credential (JSON распарсен, служебные *_json убраны). */
function toCredential(row) {
  if (!row) return null;
  const { injection_json, window_json, filter_json, ...rest } = row;
  return {
    ...rest,
    injection: JSON.parse(injection_json),
    window: window_json ? JSON.parse(window_json) : null,
    filter: filter_json ? JSON.parse(filter_json) : null,
  };
}

/** Строка agents → объект Agent без token_hash (хэш токена наружу не отдаём). */
function toAgent(row) {
  if (!row) return null;
  const { token_hash, ...rest } = row;
  return rest;
}

/** Строка pending_actions → объект с разобранным body (body_json остаётся в строке). */
function toPending(row) {
  if (!row) return null;
  return { ...row, body: JSON.parse(row.body_json) };
}

/** Единственный пользователь до миграции команды (users, этап 6.x): user_id сессий и шагов TOTP. */
export const OWNER_USER_ID = 'owner';

// Таблицы демо-сброса в порядке, допустимом для внешних ключей (дочерние раньше родительских)
const DEMO_WIPE_TABLES = ['pending_actions', 'leases', 'grants', 'requests', 'agent_credentials', 'agents', 'credentials',
  'sessions', 'backup_codes', 'totp_used', 'one_time_links', 'owner'];

/** opts.demo: методы demo* (в том числе demoWipe) существуют только в демо-режиме (GW_DEMO=1). */
export function createRepo(db, { demo = false } = {}) {
  const st = {
    // meta
    getMeta: db.prepare('SELECT value FROM meta WHERE key = ?'),
    setMeta: db.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)'),

    // owner (единственная строка id=1)
    ensureOwner: db.prepare('INSERT OR IGNORE INTO owner (id) VALUES (1)'),
    getOwner: db.prepare('SELECT * FROM owner WHERE id = 1'),
    setPasswordHash: db.prepare('UPDATE owner SET password_hash = ? WHERE id = 1'),
    setTotp: db.prepare('UPDATE owner SET totp_secret_enc = ?, totp_enabled = ? WHERE id = 1'),
    setTg: db.prepare('UPDATE owner SET tg_chat_id = ?, tg_bot_param = ? WHERE id = 1'),
    setSetupDone: db.prepare('UPDATE owner SET setup_done = 1 WHERE id = 1'),

    // backup codes
    delCodes: db.prepare('DELETE FROM backup_codes'),
    insCode: db.prepare('INSERT INTO backup_codes (code_hash) VALUES (?)'),
    useCode: db.prepare('UPDATE backup_codes SET used_at = unixepoch() WHERE code_hash = ? AND used_at IS NULL'),

    // sessions
    insSession: db.prepare('INSERT INTO sessions (id_hash, user_id, expires_at, ua) VALUES (?, ?, ?, ?)'),
    getSession: db.prepare('SELECT * FROM sessions WHERE id_hash = ? AND expires_at > unixepoch()'),
    touchSession: db.prepare('UPDATE sessions SET expires_at = ?, last_seen_at = unixepoch() WHERE id_hash = ?'),
    setSessionTotp: db.prepare('UPDATE sessions SET totp_ok = 1, totp_at = unixepoch() WHERE id_hash = ?'),
    countFullSessions: db.prepare('SELECT count(*) AS n FROM sessions WHERE totp_ok = 1 AND expires_at > unixepoch()'),
    delSession: db.prepare('DELETE FROM sessions WHERE id_hash = ?'),
    delAllSessions: db.prepare('DELETE FROM sessions'),
    // при равном last_seen_at (секундная точность) новее считается вставленная позже (rowid)
    listSessions: db.prepare('SELECT * FROM sessions WHERE expires_at > unixepoch() ORDER BY last_seen_at DESC, rowid DESC'),

    // использованные шаги TOTP (П-32)
    takeTotpStep: db.prepare('INSERT OR IGNORE INTO totp_used (user_id, step) VALUES (?, ?)'),
    purgeTotpSteps: db.prepare('DELETE FROM totp_used WHERE used_at < unixepoch() - 600'),

    // черновики действий при 2FA (П-19); время сравнения передаёт вызывающий (подмена часов в тестах)
    savePending: db.prepare(
      'INSERT OR REPLACE INTO pending_actions (id, session_hash, user_id, type, target_id, version, body_json, created_at, expires_at) ' +
        'VALUES (@id, @session_hash, @user_id, @type, @target_id, @version, @body_json, COALESCE(@created_at, unixepoch()), @expires_at)',
    ),
    getPending: db.prepare('SELECT * FROM pending_actions WHERE id = ? AND session_hash = ? AND expires_at > COALESCE(?, unixepoch())'),
    consumePending: db.prepare(
      'DELETE FROM pending_actions WHERE id = ? AND session_hash = ? AND expires_at > COALESCE(?, unixepoch()) RETURNING *',
    ),
    delPending: db.prepare('DELETE FROM pending_actions WHERE session_hash = ?'),
    purgePending: db.prepare('DELETE FROM pending_actions WHERE expires_at <= COALESCE(?, unixepoch())'),

    // one-time links
    insLink: db.prepare('INSERT INTO one_time_links (token_hash, purpose, expires_at) VALUES (?, ?, ?)'),
    consumeLink: db.prepare(
      'UPDATE one_time_links SET used_at = unixepoch() ' +
        'WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > unixepoch()',
    ),

    // credentials
    insCredential: db.prepare(
      'INSERT INTO credentials (id, provider, label, kind, host, injection_json, vault_param, mode, approval, ' +
        'max_ttl, max_calls, max_parallel, window_json, expires_at, always_until, last4, created_at) ' +
        'VALUES (@id, @provider, @label, @kind, @host, @injection_json, @vault_param, @mode, @approval, ' +
        '@max_ttl, @max_calls, @max_parallel, @window_json, @expires_at, @always_until, @last4, COALESCE(@created_at, unixepoch()))',
    ),
    getCredential: db.prepare('SELECT * FROM credentials WHERE id = ? AND deleted_at IS NULL'),
    getCredentialRaw: db.prepare('SELECT * FROM credentials WHERE id = ?'),
    listCredentials: db.prepare('SELECT * FROM credentials WHERE deleted_at IS NULL ORDER BY created_at, id'),
    updateCredentialPolicy: db.prepare(
      'UPDATE credentials SET label = @label, mode = @mode, approval = @approval, max_ttl = @max_ttl, ' +
        'max_calls = @max_calls, max_parallel = @max_parallel, window_json = @window_json, expires_at = @expires_at, ' +
        'always_until = @always_until WHERE id = @id',
    ),
    listExpiredAlways: db.prepare(
      "SELECT * FROM credentials WHERE mode = 'always' AND always_until IS NOT NULL " +
        'AND always_until <= unixepoch() AND deleted_at IS NULL',
    ),
    endAlways: db.prepare(
      "UPDATE credentials SET mode = 'ask', always_until = NULL WHERE id = ? AND mode = 'always' " +
        'AND always_until IS NOT NULL AND always_until <= unixepoch()',
    ),
    softDeleteCredential: db.prepare(
      'UPDATE credentials SET deleted_at = COALESCE(deleted_at, unixepoch()) WHERE id = ?',
    ),
    revokeCredentialGrants: db.prepare(
      'UPDATE grants SET revoked_at = unixepoch() WHERE credential_id = ? AND revoked_at IS NULL',
    ),
    updateCredentialFilter: db.prepare('UPDATE credentials SET filter_json = ? WHERE id = ?'),
    listCredentialsByProvider: db.prepare('SELECT * FROM credentials WHERE provider = ? AND deleted_at IS NULL ORDER BY created_at, id'),
    setCredentialProvider: db.prepare('UPDATE credentials SET provider = @to WHERE id = @id AND provider = @from AND deleted_at IS NULL'),
    updateCredentialSecretMeta: db.prepare(
      'UPDATE credentials SET last4 = COALESCE(?, last4), vault_param = COALESCE(?, vault_param) WHERE id = ?',
    ),

    // agents
    insAgent: db.prepare(
      'INSERT INTO agents (id, name, token_hash, enabled, all_credentials, created_at, last_seen_at) ' +
        'VALUES (@id, @name, @token_hash, @enabled, @all_credentials, COALESCE(@created_at, unixepoch()), @last_seen_at)',
    ),
    getAgent: db.prepare('SELECT * FROM agents WHERE id = ?'),
    getAgentByTokenHash: db.prepare('SELECT * FROM agents WHERE token_hash = ?'),
    listAgents: db.prepare('SELECT * FROM agents ORDER BY created_at, id'),
    setAgentEnabled: db.prepare('UPDATE agents SET enabled = ? WHERE id = ?'),
    revokeAgentGrants: db.prepare('UPDATE grants SET revoked_at = unixepoch() WHERE agent_id = ? AND revoked_at IS NULL'),
    delAgent: db.prepare('DELETE FROM agents WHERE id = ?'),
    touchAgent: db.prepare('UPDATE agents SET last_seen_at = unixepoch() WHERE id = ?'),
    setAgentAll: db.prepare('UPDATE agents SET all_credentials = ? WHERE id = ?'),
    listAgentCreds: db.prepare('SELECT credential_id FROM agent_credentials WHERE agent_id = ? ORDER BY credential_id'),
    delAgentCreds: db.prepare('DELETE FROM agent_credentials WHERE agent_id = ?'),
    insAgentCred: db.prepare('INSERT OR IGNORE INTO agent_credentials (agent_id, credential_id) VALUES (?, ?)'),
    agentCanUse: db.prepare(
      `SELECT 1 FROM agents a WHERE a.id = @agent AND (a.all_credentials = 1
         OR EXISTS (SELECT 1 FROM agent_credentials ac WHERE ac.agent_id = a.id AND ac.credential_id = @cred))`,
    ),
    // Пропуска к ключам, которые агенту больше не доступны после смены привязки
    revokeUnboundGrants: db.prepare(
      `UPDATE grants SET revoked_at = unixepoch()
       WHERE agent_id = @agent AND revoked_at IS NULL
         AND NOT EXISTS (SELECT 1 FROM agents a WHERE a.id = @agent AND a.all_credentials = 1)
         AND credential_id NOT IN (SELECT credential_id FROM agent_credentials WHERE agent_id = @agent)`,
    ),

    // статистика для страницы «Запросы»
    callStats: db.prepare(
      `SELECT json_extract(meta_json, '$.agent') AS agent_id,
              json_extract(meta_json, '$.credential') AS credential_id,
              count(*) AS calls,
              sum(CASE WHEN coalesce(json_extract(meta_json, '$.status'), 0) BETWEEN 200 AND 399 THEN 0 ELSE 1 END) AS errors,
              max(at) AS last_at
       FROM audit WHERE action = 'proxy.call' AND at >= unixepoch() - @days * 86400
       GROUP BY 1, 2`,
    ),
    requestStats: db.prepare(
      `SELECT agent_id, credential_id, count(*) AS total,
              sum(status = 'approved') AS approved, sum(status = 'denied') AS denied,
              sum(status IN ('pending', 'expired')) AS unanswered
       FROM requests WHERE created_at >= unixepoch() - @days * 86400
       GROUP BY 1, 2`,
    ),
    countOkCalls: db.prepare(
      "SELECT count(*) AS n FROM audit WHERE action = 'proxy.call' AND coalesce(json_extract(meta_json, '$.status'), 0) BETWEEN 200 AND 299",
    ),
    listCalls: db.prepare(
      `SELECT id, at, target, json_extract(meta_json, '$.agent') AS agent_id,
              json_extract(meta_json, '$.credential') AS credential_id,
              json_extract(meta_json, '$.status') AS status, json_extract(meta_json, '$.ms') AS ms
       FROM audit WHERE action = 'proxy.call' AND at >= unixepoch() - @days * 86400
         AND (@agent IS NULL OR json_extract(meta_json, '$.agent') = @agent)
       ORDER BY id DESC LIMIT @limit`,
    ),

    // requests
    insRequest: db.prepare(
      'INSERT INTO requests (id, agent_id, credential_id, ttl, calls, reason, status, created_at, expires_at) ' +
        "VALUES (@id, @agent_id, @credential_id, @ttl, @calls, @reason, COALESCE(@status, 'pending'), " +
        'COALESCE(@created_at, unixepoch()), @expires_at)',
    ),
    getRequest: db.prepare('SELECT * FROM requests WHERE id = ?'),
    listPending: db.prepare(
      'SELECT r.*, a.name AS agent_name, c.label AS credential_label, c.provider AS provider ' +
        'FROM requests r ' +
        'JOIN agents a ON a.id = r.agent_id ' +
        'JOIN credentials c ON c.id = r.credential_id ' +
        "WHERE r.status = 'pending' AND r.expires_at > unixepoch() " +
        'ORDER BY r.created_at, r.id',
    ),
    countPendingPair: db.prepare(
      "SELECT count(*) AS n FROM requests WHERE status = 'pending' AND expires_at > unixepoch() AND agent_id = ? AND credential_id = ?",
    ),
    countPendingAgent: db.prepare(
      "SELECT count(*) AS n FROM requests WHERE status = 'pending' AND expires_at > unixepoch() AND agent_id = ?",
    ),
    decideRequest: db.prepare(
      "UPDATE requests SET status = ?, decided_at = unixepoch(), decided_via = ? WHERE id = ? AND status = 'pending'",
    ),
    approveRequest: db.prepare(
      "UPDATE requests SET status = 'approved', decided_at = unixepoch(), decided_via = ? WHERE id = ? AND status = 'pending' AND expires_at > unixepoch()",
    ),
    expireRequests: db.prepare(
      "UPDATE requests SET status = 'expired', decided_via = 'timeout', decided_at = unixepoch() " +
        "WHERE status = 'pending' AND expires_at < unixepoch()",
    ),
    setRequestTgMessage: db.prepare('UPDATE requests SET tg_message_id = ? WHERE id = ?'),

    // grants
    insGrant: db.prepare(
      'INSERT INTO grants (id, request_id, agent_id, credential_id, created_at, expires_at, ' +
        'max_calls, calls_used, max_parallel, inflight, revoked_at) ' +
        'VALUES (@id, @request_id, @agent_id, @credential_id, COALESCE(@created_at, unixepoch()), @expires_at, ' +
        '@max_calls, 0, @max_parallel, 0, NULL)',
    ),
    getGrant: db.prepare('SELECT * FROM grants WHERE id = ?'),
    // Квота и параллельность в одном UPDATE: changes()=0 значит, что условие не выполнено.
    reserveGrant: db.prepare(
      'UPDATE grants SET calls_used = calls_used + 1, inflight = inflight + 1 ' +
        'WHERE id = ? AND revoked_at IS NULL AND expires_at > unixepoch() ' +
        'AND calls_used < max_calls AND inflight < max_parallel',
    ),
    insLease: db.prepare('INSERT INTO leases (grant_id, expires_at) VALUES (?, unixepoch() + ?)'),
    // DELETE ... RETURNING: удаляем lease и получаем grant_id; пустой результат = lease уже нет (no-op).
    delLease: db.prepare('DELETE FROM leases WHERE id = ? RETURNING grant_id'),
    extendLease: db.prepare('UPDATE leases SET expires_at = unixepoch() + ? WHERE id = ?'),
    reapExpiredLeases: db.prepare('DELETE FROM leases WHERE expires_at < unixepoch() RETURNING grant_id'),
    decInflight: db.prepare('UPDATE grants SET inflight = MAX(inflight - 1, 0) WHERE id = ?'),
    revokeGrant: db.prepare('UPDATE grants SET revoked_at = unixepoch() WHERE id = ? AND revoked_at IS NULL'),
    revokeAllGrants: db.prepare('UPDATE grants SET revoked_at = unixepoch() WHERE revoked_at IS NULL'),
    // restore/init: сброс незавершённых состояний (П-35)
    expireAllPending: db.prepare(
      "UPDATE requests SET status = 'expired', decided_at = unixepoch(), decided_via = 'timeout' WHERE status = 'pending'",
    ),
    delTempMeta: db.prepare(
      "DELETE FROM meta WHERE key IN ('setup_totp_secret','setup_backup_codes','setup_codes_saved','setup_tg_code','reissue_totp_secret','new_backup_codes') OR key LIKE 'pending:%'",
    ),
    delAllTotpSteps: db.prepare('DELETE FROM totp_used'),
    delAllLinks: db.prepare('DELETE FROM one_time_links'),
    resetOwnerSetup: db.prepare('UPDATE owner SET password_hash = NULL, totp_secret_enc = NULL, totp_enabled = 0, tg_chat_id = NULL, tg_bot_param = NULL, setup_done = 0 WHERE id = 1'),
    delAllBackupCodes: db.prepare('DELETE FROM backup_codes'),
    // ротация аудита (П-37)
    auditOlder: db.prepare('SELECT * FROM audit WHERE at < ? ORDER BY id'),
    auditCutoff: db.prepare('SELECT unixepoch() - ? AS cutoff'),
    listActiveGrants: db.prepare(
      'SELECT * FROM grants WHERE revoked_at IS NULL AND expires_at > unixepoch() ORDER BY created_at, id',
    ),

    // audit (только INSERT/SELECT; UPDATE/DELETE запрещены триггерами схемы)
    insAudit: db.prepare('INSERT INTO audit (actor, action, target, meta_json) VALUES (?, ?, ?, ?)'),
    listAudit: db.prepare(
      'SELECT * FROM audit WHERE (@before IS NULL OR id < @before) ORDER BY id DESC LIMIT @limit',
    ),
  };

  // ---- транзакции (создаются один раз) ----

  // Запись владельца: гарантируем строку id=1, затем пишем.
  const ownerWrite = db.transaction((stmt, params) => {
    st.ensureOwner.run();
    return stmt.run(...params);
  });

  const replaceCodes = db.transaction((hashes) => {
    st.delCodes.run();
    for (const h of hashes) st.insCode.run(h);
  });

  const reserveTx = db.transaction((grantId, leaseTtlSec) => {
    const r = st.reserveGrant.run(grantId);
    if (r.changes === 0) return null;
    return Number(st.insLease.run(grantId, leaseTtlSec).lastInsertRowid);
  });

  const releaseTx = db.transaction((leaseId) => {
    const row = st.delLease.get(leaseId);
    if (!row) return false;
    st.decInflight.run(row.grant_id);
    return true;
  });

  const reapTx = db.transaction(() => {
    const rows = st.reapExpiredLeases.all();
    for (const row of rows) st.decInflight.run(row.grant_id);
    return rows.length;
  });

  const softDeleteCredentialTx = db.transaction((id) => {
    const r = st.softDeleteCredential.run(id);
    st.revokeCredentialGrants.run(id);
    return r.changes === 1;
  });

  // Сброс незавершённых состояний после restore/init: пропуска, сессии, ссылки, ожидающие заявки,
  // временные секреты 2FA/мастера в meta, использованные шаги TOTP. Одна транзакция.
  const resetPendingTx = db.transaction(() => ({
    grants: st.revokeAllGrants.run().changes,
    sessions: st.delAllSessions.run().changes,
    links: st.delAllLinks.run().changes,
    requests: st.expireAllPending.run().changes,
    meta: st.delTempMeta.run().changes,
    totpSteps: st.delAllTotpSteps.run().changes,
  }));

  // Ротация аудита (П-37): триггеры запрещают DELETE/UPDATE, поэтому таблица пересоздаётся.
  // writeArchive(rows) -> string вызывается синхронно ДО подмены таблицы; если бросает, транзакция откатывается.
  const rotateAuditTx = db.transaction((days, writeArchive) => {
    const cutoff = st.auditCutoff.get(days * 86400).cutoff;
    const old = st.auditOlder.all(cutoff);
    if (!old.length) return { archived: 0, cutoff, file: null };
    const file = writeArchive(old);
    const seq = db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'audit'").get()?.seq ?? 0;
    // схема новой таблицы берётся из schema.sql (CREATE TABLE audit), чтобы не дублировать SQL
    db.exec(AUDIT_TABLE_DDL.replace('IF NOT EXISTS audit (', 'audit_new ('));
    db.prepare('INSERT INTO audit_new SELECT * FROM audit WHERE at >= ?').run(cutoff);
    db.exec("DELETE FROM sqlite_sequence WHERE name = 'audit_new'");
    db.prepare("INSERT INTO sqlite_sequence (name, seq) VALUES ('audit_new', ?)").run(seq);
    db.exec('DROP TABLE audit; ALTER TABLE audit_new RENAME TO audit;');
    db.exec(AUDIT_DDL); // индексы и оба триггера append-only (таблица уже есть, IF NOT EXISTS)
    st.insAudit.run('system', 'audit.rotated', null, JSON.stringify({ archived: old.length, cutoff, file: String(file).split(/[\\/]/).pop() }));
    return { archived: old.length, cutoff, file };
  });

  const setAgentEnabledTx =db.transaction((id, enabled) => {
    const r = st.setAgentEnabled.run(enabled ? 1 : 0, id);
    if (!enabled) st.revokeAgentGrants.run(id);
    return r.changes === 1;
  });

  // Привязка ключей: флаг «все» + список; пропуска к отвязанным ключам отзываются в той же транзакции.
  const setAgentCredentialsTx = db.transaction((agentId, all, ids) => {
    if (st.setAgentAll.run(all ? 1 : 0, agentId).changes !== 1) return false;
    st.delAgentCreds.run(agentId);
    for (const id of ids) if (st.getCredential.get(id)) st.insAgentCred.run(agentId, id);
    st.revokeUnboundGrants.run({ agent: agentId });
    return true;
  });

  const updatePolicyTx = db.transaction((id, patch) => {
    const cur = st.getCredentialRaw.get(id);
    if (!cur) return false;
    // Читаем текущую строку, накладываем переданные поля, пишем одним UPDATE.
    // expires_at и window могут быть явно сброшены в null, поэтому проверяем наличие ключа.
    const pick = (key) => (key in patch && patch[key] !== undefined ? patch[key] : cur[key]);
    st.updateCredentialPolicy.run({
      id,
      label: pick('label'),
      mode: pick('mode'),
      approval: pick('approval'),
      max_ttl: pick('max_ttl'),
      max_calls: pick('max_calls'),
      max_parallel: pick('max_parallel'),
      window_json:
        'window' in patch ? (patch.window ? JSON.stringify(patch.window) : null) : cur.window_json,
      expires_at: 'expires_at' in patch ? patch.expires_at : cur.expires_at,
      always_until: 'always_until' in patch ? patch.always_until : cur.always_until,
    });
    return true;
  });

  // Ключи, у которых кончилось время «без вопросов», переводятся в 'ask'; возвращаем их для уведомлений.
  const endExpiredAlwaysTx = db.transaction(() => {
    const ended = [];
    for (const row of st.listExpiredAlways.all()) {
      if (st.endAlways.run(row.id).changes === 1) ended.push(toCredential({ ...row, mode: 'ask', always_until: null }));
    }
    return ended;
  });

  const decideTx = (id, status, via) => {
    if (status !== 'approved' && status !== 'denied') {
      throw new Error(`invalid decision status: ${status}`);
    }
    return st.decideRequest.run(status, via, id).changes === 1;
  };

  // Одобрение и пропуск — одной транзакцией: одобренная заявка без пропуска и два пропуска на заявку невозможны (П-10)
  const approveTx = db.transaction((id, via, grant) => {
    if (st.approveRequest.run(via, id).changes !== 1) return false;
    st.insGrant.run({
      id: grant.id, request_id: id, agent_id: grant.agent_id, credential_id: grant.credential_id,
      created_at: grant.created_at ?? null, expires_at: grant.expires_at, max_calls: grant.max_calls, max_parallel: grant.max_parallel,
    });
    return true;
  });

  // Демо (П-20): полная очистка одной транзакцией. Триггер append-only на audit снимается и ставится заново
  // (AUDIT_DDL идемпотентен). csrf_key остаётся: ключ HMAC уже загружен в память плагина CSRF.
  const demoApi = demo ? (() => {
    const q = {
      foreignCredentials: db.prepare("SELECT id FROM credentials WHERE provider <> 'demo' ORDER BY id"),
      notifyMeta: db.prepare("SELECT count(*) AS n FROM meta WHERE key LIKE 'notify.%'"),
      resetAge: db.prepare("SELECT unixepoch() - CAST(value AS INTEGER) AS age FROM meta WHERE key = 'demo_reset_at'"),
      markReset: db.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES ('demo_reset_at', CAST(unixepoch() AS TEXT))"),
    };
    // Удаление объекта посетителя вместе с историей: при потолке демо уступает место новым
    const evict = (column, table, tableId) => {
      const leases = db.prepare(`DELETE FROM leases WHERE grant_id IN (SELECT id FROM grants WHERE ${column} = ?)`);
      const grants = db.prepare(`DELETE FROM grants WHERE ${column} = ?`);
      const requests = db.prepare(`DELETE FROM requests WHERE ${column} = ?`);
      const bindings = db.prepare(`DELETE FROM agent_credentials WHERE ${column} = ?`);
      const row = db.prepare(`DELETE FROM ${table} WHERE ${tableId} = ?`);
      return db.transaction((id) => { for (const s of [leases, grants, requests, bindings, row]) s.run(id); });
    };
    const evictAgentTx = evict('agent_id', 'agents', 'id');
    const evictCredentialTx = evict('credential_id', 'credentials', 'id');
    const wipeTx = db.transaction(() => {
      for (const tbl of DEMO_WIPE_TABLES) db.exec(`DELETE FROM ${tbl}`);
      db.exec("DELETE FROM meta WHERE key <> 'csrf_key'");
      db.exec('DROP TRIGGER IF EXISTS audit_no_delete');
      db.exec('DELETE FROM audit');
      db.exec("DELETE FROM sqlite_sequence WHERE name IN ('audit', 'leases', 'backup_codes')");
      db.exec(AUDIT_DDL);
    });
    return {
      /** Очистка всех таблиц (кроме meta.csrf_key). Существует только при createRepo(db, { demo: true }). */
      demoWipe() { wipeTx(); },
      /** Удаляет агента посетителя с заявками, пропусками и привязками. */
      demoEvictAgent(id) { evictAgentTx(id); },
      /** Удаляет запись ключа посетителя с заявками, пропусками и привязками; значение в сейфе удаляет вызывающий. */
      demoEvictCredential(id) { evictCredentialTx(id); },
      /** Факты для assertDemoIsolation: id чужих ключей (включая удалённые), Telegram, каналы уведомлений, пароль владельца. */
      demoIsolationFacts() {
        const o = st.getOwner.get();
        return {
          foreignCredentialIds: q.foreignCredentials.all().map((r) => r.id),
          ownerTelegram: !!(o && (o.tg_chat_id !== null || o.tg_bot_param !== null)),
          notifyMeta: q.notifyMeta.get().n > 0,
          ownerPassword: !!(o && o.password_hash),
        };
      },
      /** Секунд с последнего сброса (по unixepoch() SQLite) или null, если сброса не было. */
      demoResetAge() { return q.resetAge.get()?.age ?? null; },
      demoMarkReset() { q.markReset.run(); },
    };
  })() : {};

  return {
    ...demoApi,
    // ---- meta ----
    getMeta(key) {
      return st.getMeta.get(key)?.value ?? null;
    },
    setMeta(key, value) {
      st.setMeta.run(key, String(value));
    },

    // ---- owner ----
    getOwner() {
      return orNull(st.getOwner.get());
    },
    setPasswordHash(hash) {
      ownerWrite(st.setPasswordHash, [hash]);
    },
    setTotp(secretEnc, enabled) {
      ownerWrite(st.setTotp, [secretEnc, enabled ? 1 : 0]);
    },
    setTg(chatId, botParam) {
      ownerWrite(st.setTg, [chatId ?? null, botParam ?? null]);
    },
    setSetupDone() {
      ownerWrite(st.setSetupDone, []);
    },

    // ---- backup codes ----
    replaceBackupCodes(hashes) {
      replaceCodes(hashes);
    },
    useBackupCode(hash) {
      return st.useCode.run(hash).changes === 1;
    },

    // ---- sessions ----
    // Везде идентификатор — idHash = sha256(cookie) hex; сырой id сюда не попадает (считает auth/session.js, Н-3).
    // user_id пока константа владельца без FK: таблица users появится с миграцией команды.
    createSession(idHash, expiresAt, ua, userId = OWNER_USER_ID) {
      st.insSession.run(idHash, userId, expiresAt, ua ?? null);
    },
    getSession(idHash) {
      return orNull(st.getSession.get(idHash));
    },
    setSessionTotp(idHash) { return st.setSessionTotp.run(idHash).changes === 1; },
    countFullSessions() { return st.countFullSessions.get().n; },
    touchSession(idHash, newExpiresAt) {
      st.touchSession.run(newExpiresAt, idHash);
    },
    deleteSession(idHash) {
      st.delSession.run(idHash);
    },
    deleteAllSessions() {
      st.delAllSessions.run();
    },
    listSessions() {
      return st.listSessions.all();
    },

    // ---- использованные шаги TOTP (П-32) ----
    /** true, если шаг взят впервые; повторный (и после перезапуска) — false. Атомарно: INSERT OR IGNORE. */
    takeTotpStep(userId, step) {
      return st.takeTotpStep.run(userId, step).changes === 1;
    },
    /** Удаляет шаги старше 10 минут (reap-цикл); -> сколько удалено. */
    purgeTotpSteps() {
      return st.purgeTotpSteps.run().changes;
    },

    // ---- черновики действий при 2FA (П-19) ----
    /** Одна запись на сессию: прежняя (и её id) заменяется. body — объект allowlist, в базе JSON. */
    savePending(sessionHash, { id, userId, type, targetId, version, body, expiresAt, createdAt }) {
      st.savePending.run({
        id, session_hash: sessionHash, user_id: userId, type, target_id: targetId, version,
        body_json: JSON.stringify(body), created_at: createdAt ?? null, expires_at: expiresAt,
      });
    },
    /** -> строка (с разобранным body) | null: нет, чужая сессия или просрочена. nowSec — подмена часов, по умолчанию unixepoch(). */
    getPending(sessionHash, id, nowSec) {
      return toPending(st.getPending.get(id, sessionHash, nowSec ?? null));
    },
    /** DELETE ... RETURNING: -> строка | null. Вызывать только внутри inTransaction вместе с исполнением действия. */
    consumePending(sessionHash, id, nowSec) {
      return toPending(st.consumePending.get(id, sessionHash, nowSec ?? null));
    },
    /** Отмена, выход, смена пароля: удаляет черновик сессии. -> bool */
    deletePending(sessionHash) {
      return st.delPending.run(sessionHash).changes > 0;
    },
    /** Просроченные черновики (reap-цикл). -> сколько удалено */
    purgePending(nowSec) {
      return st.purgePending.run(nowSec ?? null).changes;
    },
    /** Выполняет fn в одной синхронной транзакции BEGIN IMMEDIATE; исключение откатывает всё. fn без await. */
    inTransaction(fn) {
      return db.transaction(fn).immediate();
    },

    // ---- one-time links ----
    createLink(tokenHash, purpose, expiresAt) {
      st.insLink.run(tokenHash, purpose, expiresAt);
    },
    consumeLink(tokenHash, purpose) {
      return st.consumeLink.run(tokenHash, purpose).changes === 1;
    },

    // ---- credentials ----
    createCredential(cred) {
      st.insCredential.run({
        id: cred.id,
        provider: cred.provider,
        label: cred.label,
        kind: cred.kind,
        host: cred.host,
        injection_json: JSON.stringify(cred.injection),
        vault_param: cred.vault_param,
        mode: cred.mode ?? 'ask',
        approval: cred.approval ?? 'web_button',
        max_ttl: cred.max_ttl ?? 3600,
        max_calls: cred.max_calls ?? 100,
        max_parallel: cred.max_parallel ?? 2,
        window_json: cred.window ? JSON.stringify(cred.window) : null,
        expires_at: cred.expires_at ?? null,
        always_until: cred.always_until ?? null,
        last4: cred.last4,
        created_at: cred.created_at ?? null,
      });
    },
    getCredential(id) {
      return toCredential(st.getCredential.get(id));
    },
    listCredentials() {
      return st.listCredentials.all().map(toCredential);
    },
    updateCredentialPolicy(id, patch) {
      return updatePolicyTx(id, patch);
    },
    endExpiredAlways() {
      return endExpiredAlwaysTx();
    },
    softDeleteCredential(id) {
      return softDeleteCredentialTx(id);
    },
    updateCredentialSecretMeta(id, { last4, vault_param } = {}) {
      st.updateCredentialSecretMeta.run(last4 ?? null, vault_param ?? null, id);
    },
    updateCredentialFilter(id, filter) {
      st.updateCredentialFilter.run(filter ? JSON.stringify(filter) : null, id);
    },
    /** Действующие ключи одного провайдера (для миграции каталога). */
    listCredentialsByProvider(slug) {
      return st.listCredentialsByProvider.all(slug).map(toCredential);
    },
    /** Смена провайдера ключа и запись в audit `catalog.migrated` — одна транзакция; секрет в сейфе не трогается. -> bool */
    migrateCredentialProvider(id, from, to) {
      return db.transaction(() => {
        if (st.setCredentialProvider.run({ id, from, to }).changes !== 1) return false;
        st.insAudit.run('system', 'catalog.migrated', id, JSON.stringify({ from, to }));
        return true;
      })();
    },

    // ---- agents ----
    createAgent(agent) {
      st.insAgent.run({
        id: agent.id,
        name: agent.name,
        token_hash: agent.token_hash,
        enabled: agent.enabled ?? 1,
        all_credentials: agent.all_credentials ?? 1,
        created_at: agent.created_at ?? null,
        last_seen_at: agent.last_seen_at ?? null,
      });
    },
    getAgent(id) {
      return toAgent(st.getAgent.get(id)) ?? null;
    },
    getAgentByTokenHash(hash) {
      return toAgent(st.getAgentByTokenHash.get(hash)) ?? null;
    },
    listAgents() {
      return st.listAgents.all().map(toAgent);
    },
    setAgentEnabled(id, enabled) {
      return setAgentEnabledTx(id, Boolean(enabled));
    },
    /** Создан ли уникальный индекс «один пропуск на заявку» (П-10); в старой базе с дубликатами его нет. */
    hasGrantsRequestIndex() {
      return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'grants_request'").get();
    },
    deleteAgent(id) {
      return st.delAgent.run(id).changes === 1;
    },
    touchAgent(id) {
      st.touchAgent.run(id);
    },
    listAgentCredentials(agentId) {
      return st.listAgentCreds.all(agentId).map((r) => r.credential_id);
    },
    setAgentCredentials(agentId, { all, ids = [] }) {
      return setAgentCredentialsTx(agentId, Boolean(all), [...new Set(ids.map(String))]);
    },
    agentCanUse(agentId, credentialId) {
      return !!st.agentCanUse.get({ agent: agentId, cred: credentialId });
    },

    // ---- статистика ----
    // Период — число дней назад от текущего момента (время считает SQLite).
    callStats(days) {
      return st.callStats.all({ days: Number(days) });
    },
    requestStats(days) {
      return st.requestStats.all({ days: Number(days) });
    },
    /** Число успешных (2xx) вызовов прокси за всё время: для экрана «It works» онбординга. */
    countOkCalls() {
      return st.countOkCalls.get().n;
    },
    listCalls({ days, agentId = null, limit = 50 } = {}) {
      return st.listCalls.all({ days: Number(days), agent: agentId, limit: Number(limit) });
    },

    // ---- requests ----
    createRequest(req) {
      st.insRequest.run({
        id: req.id,
        agent_id: req.agent_id,
        credential_id: req.credential_id,
        ttl: req.ttl,
        calls: req.calls,
        reason: req.reason ?? '',
        status: req.status ?? null,
        created_at: req.created_at ?? null,
        expires_at: req.expires_at,
      });
    },
    getRequest(id) {
      return orNull(st.getRequest.get(id));
    },
    listPending() {
      return st.listPending.all();
    },
    /** Ожидающие (не истёкшие) заявки: на пару агент+ключ и всего у агента (потолок Н-6) */
    countPendingRequests(agentId, credentialId) {
      return { pair: st.countPendingPair.get(agentId, credentialId).n, agent: st.countPendingAgent.get(agentId).n };
    },
    decideRequest(id, status, via) {
      return decideTx(id, status, via);
    },
    /** pending → approved и создание grant атомарно; false — заявка уже не ждёт решения или истекла */
    approveRequest(id, via, grant) {
      return approveTx(id, via, grant);
    },
    expireRequests() {
      return st.expireRequests.run().changes;
    },
    setRequestTgMessage(id, messageId) {
      st.setRequestTgMessage.run(messageId, id);
    },

    // ---- grants ----
    createGrant(grant) {
      st.insGrant.run({
        id: grant.id,
        request_id: grant.request_id,
        agent_id: grant.agent_id,
        credential_id: grant.credential_id,
        created_at: grant.created_at ?? null,
        expires_at: grant.expires_at,
        max_calls: grant.max_calls,
        max_parallel: grant.max_parallel,
      });
    },
    getGrant(id) {
      return orNull(st.getGrant.get(id));
    },
    reserveCall(grantId, leaseTtlSec) {
      return reserveTx(grantId, leaseTtlSec);
    },
    releaseCall(leaseId) {
      return releaseTx(leaseId);
    },
    extendLease(leaseId, ttlSec) {
      return st.extendLease.run(ttlSec, leaseId).changes === 1;
    },
    reapLeases() {
      return reapTx();
    },
    revokeGrant(id) {
      return st.revokeGrant.run(id).changes === 1;
    },
    revokeAllGrants() {
      return st.revokeAllGrants.run().changes;
    },
    listActiveGrants() {
      return st.listActiveGrants.all();
    },
    /** restore/init: отзыв пропусков, сессии, ссылки, pending-заявки -> expired, временные секреты, шаги TOTP; -> счётчики */
    resetPendingStates() {
      return resetPendingTx();
    },
    /** init: пароль, 2FA, Telegram, резервные коды и мастер заново (ключи и агенты остаются) */
    resetOwnerSetup() {
      st.resetOwnerSetup.run();
      st.delAllBackupCodes.run();
    },
    deleteAllLinks() {
      return st.delAllLinks.run().changes;
    },
    /** П-37: -> { archived, cutoff, file }; запускать при остановленном шлюзе */
    rotateAudit(days, writeArchive) {
      return rotateAuditTx(days, writeArchive);
    },

    // ---- audit ----
    audit(actor, action, target, meta) {
      st.insAudit.run(actor, action, target ?? null, meta === undefined ? null : JSON.stringify(meta));
    },
    listAudit({ limit = 100, before } = {}) {
      return st.listAudit.all({ limit: Number(limit), before: before ?? null });
    },
  };
}
