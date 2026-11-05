// Пароль владельца: Argon2id 64 МиБ / 3 / 1, не больше одного хэширования одновременно (ТЗ §2, §9.7)
import argon2 from 'argon2';

const OPTS = { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 };
let chain = Promise.resolve(); // семафор на 1

function serialized(fn) {
  const run = chain.then(fn, fn);
  chain = run.catch(() => {});
  return run;
}

export function hashPassword(pw) { return serialized(() => argon2.hash(pw, OPTS)); }
export function verifyPassword(hash, pw) {
  if (!hash) return Promise.resolve(false);
  return serialized(() => argon2.verify(hash, pw).catch(() => false));
}
