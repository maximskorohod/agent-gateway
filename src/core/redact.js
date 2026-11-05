// Потоковая замена секретов на **** (ТЗ §9.2). Держит хвост длиной (maxLen-1) между чанками.
export function makeRedactor(secrets) {
  const list = (secrets || []).filter((s) => typeof s === 'string' && s.length >= 4);
  if (!list.length) return { push: (chunk) => chunk, flush: () => Buffer.alloc(0) };
  const maxLen = Math.max(...list.map((s) => Buffer.byteLength(s)));
  let tail = Buffer.alloc(0);
  const bufs = list.map((s) => Buffer.from(s));
  function replaceAll(buf) {
    let out = buf;
    for (const s of bufs) {
      let idx = out.indexOf(s);
      if (idx < 0) continue;
      const parts = [];
      let from = 0;
      while (idx >= 0) { parts.push(out.subarray(from, idx), Buffer.from('****')); from = idx + s.length; idx = out.indexOf(s, from); }
      parts.push(out.subarray(from));
      out = Buffer.concat(parts);
    }
    return out;
  }
  return {
    push(chunk) {
      const b = Buffer.concat([tail, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]);
      const r = replaceAll(b);
      const keep = Math.min(maxLen - 1, r.length);
      tail = Buffer.from(r.subarray(r.length - keep));
      return r.subarray(0, r.length - keep);
    },
    flush() { const t = tail; tail = Buffer.alloc(0); return t; },
  };
}

export function redactText(text, secrets) {
  let out = String(text);
  for (const s of secrets || []) if (s && s.length >= 4) out = out.split(s).join('****');
  return out;
}
