// Пропуска: токен HS256 {grant_id, exp}; квота и отзыв — по базе на каждом вызове (ТЗ §8)
import crypto from 'node:crypto';

const LEASE_TTL = 60;

function b64u(buf) { return Buffer.from(buf).toString('base64url'); }

export async function loadOrCreateSigningKey(vault) {
  let hex = await vault.get('sys/signing');
  if (!hex) { hex = crypto.randomBytes(32).toString('hex'); await vault.put('sys/signing', hex); }
  return Buffer.from(hex, 'hex');
}

export function createGrantService({ repo, signingKey, logger }) {
  let key = signingKey;

  function sign(payload) {
    const body = b64u(JSON.stringify(payload));
    const mac = b64u(crypto.createHmac('sha256', key).update(body).digest());
    return `gwt_${body}.${mac}`;
  }

  return {
    setKey(k) { key = k; },

    /** persist(grant) -> bool: по умолчанию просто запись; при одобрении — repo.approveRequest (одна транзакция). null — не записан. */
    issue(request, credential, persist = (g) => { repo.createGrant(g); return true; }) {
      const id = crypto.randomBytes(12).toString('base64url');
      const now = Math.floor(Date.now() / 1000);
      const grant = {
        id, request_id: request.id, agent_id: request.agent_id, credential_id: request.credential_id,
        expires_at: now + request.ttl, max_calls: request.calls, max_parallel: credential.max_parallel,
      };
      if (!persist(grant)) return null;
      const token = sign({ g: id, exp: grant.expires_at });
      return { grant: repo.getGrant(id), token };
    },

    reissueToken(grant) { return { token: sign({ g: grant.id, exp: grant.expires_at }) }; },

    verifyToken(token) {
      if (typeof token !== 'string' || !token.startsWith('gwt_')) return null;
      const [body, mac] = token.slice(4).split('.');
      if (!body || !mac) return null;
      const expected = b64u(crypto.createHmac('sha256', key).update(body).digest());
      if (expected.length !== mac.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(mac))) return null;
      let payload;
      try { payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch { return null; }
      if (!payload?.g || !payload.exp || payload.exp <= Math.floor(Date.now() / 1000)) return null;
      const grant = repo.getGrant(payload.g);
      if (!grant || grant.revoked_at || grant.expires_at <= Math.floor(Date.now() / 1000)) return null;
      return grant;
    },

    reserve(grantId) { return repo.reserveCall(grantId, LEASE_TTL); },
    release(leaseId) { if (leaseId) repo.releaseCall(leaseId); },
    extend(leaseId) { if (leaseId) repo.extendLease(leaseId, LEASE_TTL); },

    reapLoop() {
      const t = setInterval(() => {
        try { const n = repo.reapLeases(); if (n) logger.warn({ n }, 'expired leases released'); }
        catch (e) { logger.error({ err: e.message }, 'reapLeases'); }
      }, 60_000);
      t.unref();
      return t;
    },
  };
}
