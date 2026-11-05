// Простой лимитер по ключу: не больше `limit` событий за `windowSec`; блокировка `lockSec` после `lockAfter` ошибок
export function createLimiter({ limit, windowSec }) {
  const hits = new Map();
  let swept = 0; // уборка не чаще раза в секунду: иначе при большой карте каждый запрос проходит её целиком
  return {
    /** Есть ли запас, без списания: для лимитов, которые тратятся только при успехе. */
    peek(key) {
      const now = Date.now();
      return (hits.get(key) || []).filter((t) => now - t < windowSec * 1000).length < limit;
    },
    take(key) {
      const now = Date.now();
      const arr = (hits.get(key) || []).filter((t) => now - t < windowSec * 1000);
      if (arr.length >= limit) { hits.set(key, arr); return false; }
      arr.push(now); hits.set(key, arr);
      if (hits.size > 10000 && now - swept >= 1000) {
        swept = now;
        for (const [k, v] of hits) if (!v.length || now - v[v.length - 1] > windowSec * 1000) hits.delete(k);
      }
      return true;
    },
  };
}

export function createLockout({ lockAfter, lockSec }) {
  const fails = new Map(); // key -> { n, until }
  return {
    locked(key) { const f = fails.get(key); return !!f && f.until > Date.now(); },
    fail(key) {
      const f = fails.get(key) || { n: 0, until: 0 };
      f.n += 1;
      if (f.n >= lockAfter) { f.until = Date.now() + lockSec * 1000; f.n = 0; }
      fails.set(key, f);
      if (fails.size > 10000) for (const [k, v] of fails) if (v.until < Date.now() - lockSec * 1000) fails.delete(k);
      return f.until > Date.now();
    },
    reset(key) { fails.delete(key); },
  };
}
