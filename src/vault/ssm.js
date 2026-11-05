// AWS SSM Parameter Store (SecureString). Кэш 5 минут, сброс на put/del.
// П-31: гонка «старый get дописал в кэш после put/del» закрыта поколениями записей.
import { SSMClient, GetParameterCommand, PutParameterCommand, DeleteParameterCommand } from '@aws-sdk/client-ssm';

const TTL_MS = 5 * 60 * 1000;

// Второй аргумент (необязательный, нужен тестам): { client, ttlMs, now }.
// client - объект с send(cmd) вместо реального SSMClient; ttlMs - TTL кэша; now - часы (мс).
// Боевой вызов createSsmVault(config) не меняется: SSMClient с config.ssmRegion, TTL 5 минут.
export function createSsmVault(config, deps = {}) {
  const client = deps.client ?? new SSMClient({ region: config.ssmRegion });
  const ttlMs = deps.ttlMs ?? TTL_MS;
  const now = deps.now ?? Date.now;
  const cache = new Map(); // name -> { value, at }
  const gens = new Map(); // name -> поколение (растёт на каждом put/del, до и после запроса)
  const writing = new Map(); // name -> число put/del в полёте
  const full = (name) => `${config.vaultPrefix}/${name}`;
  const gen = (name) => gens.get(name) ?? 0;

  // Запись (put/del): поколение растёт ДО отправки (get, стартовавший раньше, не закэшируется)
  // и ПОСЛЕ завершения (get, стартовавший во время записи, тоже не закэшируется).
  // Кэш сбрасывается в finally, в том числе при ошибке: исход записи неизвестен.
  async function mutate(name, fn) {
    gens.set(name, gen(name) + 1);
    writing.set(name, (writing.get(name) ?? 0) + 1);
    try {
      return await fn();
    } finally {
      gens.set(name, gen(name) + 1);
      const left = (writing.get(name) ?? 1) - 1;
      if (left > 0) writing.set(name, left); else writing.delete(name);
      cache.delete(name);
    }
  }

  // Кэшируем результат только если с начала get поколение не менялось и записей в полёте нет.
  // Иначе значение отдаём вызывающему, но не кэшируем: безопаснее не помнить, чем помнить старое.
  // Следующий get после завершённой записи всегда идёт в SSM.
  function remember(name, startGen, startWriting, value) {
    if (startWriting || writing.has(name) || gen(name) !== startGen) return;
    cache.set(name, { value, at: now() });
  }

  return {
    async get(name) {
      const hit = cache.get(name);
      if (hit && now() - hit.at < ttlMs) return hit.value;
      const startGen = gen(name);
      const startWriting = writing.has(name);
      try {
        const r = await client.send(new GetParameterCommand({ Name: full(name), WithDecryption: true }));
        const value = r.Parameter?.Value ?? null;
        remember(name, startGen, startWriting, value);
        return value;
      } catch (e) {
        if (e?.name === 'ParameterNotFound') {
          remember(name, startGen, startWriting, null);
          return null;
        }
        throw e;
      }
    },
    async put(name, value) {
      await mutate(name, () => client.send(new PutParameterCommand({ Name: full(name), Value: value, Type: 'SecureString', Overwrite: true, Tier: value.length > 4096 ? 'Advanced' : 'Standard' })));
    },
    async del(name) {
      await mutate(name, async () => {
        try { await client.send(new DeleteParameterCommand({ Name: full(name) })); }
        catch (e) { if (e?.name !== 'ParameterNotFound') throw e; }
      });
    },
  };
}
