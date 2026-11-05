// Авторизация вызова и выбор ключа (П-15): одна проверка для REST и MCP, контракт access-mcp
import crypto from 'node:crypto';

export function sha256hex(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

/** Агент по токену gwa_… (хэш, enabled). Общий хелпер REST и MCP. -> agent | null */
export function authAgent(repo, token) {
  if (typeof token !== 'string' || !token.startsWith('gwa_')) return null;
  const a = repo.getAgentByTokenHash(sha256hex(token));
  return a && a.enabled ? a : null;
}

export function createAccess({ repo, catalog, grants, requests }) {
  const fail = (reason) => ({ ok: false, code: 'invalid_grant', reason });

  return {
    /**
     * Синхронная проверка вызова. Снаружи любой отказ — invalid_grant (401), причина только для debug и audit.
     * В reason нет токена, секретов и хоста.
     */
    authorizeCall({ token, provider, agentId, credentialId }) {
      const grant = grants.verifyToken(token);
      if (!grant) return fail('token');
      const agent = repo.getAgent(grant.agent_id);
      if (!agent || agent.enabled !== 1) return fail('agent_disabled');
      if (agentId !== undefined && grant.agent_id !== agentId) return fail('agent_mismatch');
      const credential = repo.getCredential(grant.credential_id);
      if (!credential) return fail('key_missing');
      if (credentialId !== undefined && credentialId !== grant.credential_id) return fail('credential_mismatch');
      const prov = catalog.get(credential.provider);
      if (!prov || prov.slug !== provider) return fail('provider_mismatch');
      if (!repo.agentCanUse(agent.id, credential.id)) return fail('not_bound');
      if (requests.credentialUsable(credential)) return fail('key_unusable');
      return { ok: true, agent, grant, credential, provider: prov };
    },

    /** Выбор ключа для заявки: чужой и несуществующий неотличимы (no_credential). */
    pickCredential({ agent, provider, credentialId }) {
      const usable = (c) => c && c.provider === provider.slug && repo.agentCanUse(agent.id, c.id);
      if (credentialId) {
        const c = repo.getCredential(String(credentialId));
        return usable(c) ? { ok: true, credential: c } : { ok: false, error: 'no_credential' };
      }
      const list = repo.listCredentials().filter(usable);
      if (list.length === 1) return { ok: true, credential: list[0] };
      if (list.length > 1) return { ok: false, error: 'credential_id_required', credentials: list.map((c) => ({ id: c.id, label: c.label })) };
      return { ok: false, error: 'no_credential' };
    },
  };
}
