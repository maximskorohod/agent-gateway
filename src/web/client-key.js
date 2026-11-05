// Ключ клиента для блокировок и лимитов: IPv4 — адрес, IPv6 — сеть /64 (у одного клиента их обычно миллионы).
// Общий хелпер сайта (web/server.js) и демо-защиты (demo/guard.js): ротация адресов внутри /64 не обходит лимиты.
/** @param {string|undefined} ip req.ip (с учётом trustProxy) @returns {string} */
export function clientKey(ip) {
  const a = String(ip || '').replace(/^::ffff:(?=\d+\.)/, '');
  if (!a.includes(':')) return a;
  const [head, tail = ''] = a.split('::');
  const h = head ? head.split(':') : [];
  const rest = tail ? tail.split(':') : [];
  const full = [...h, ...Array(Math.max(0, 8 - h.length - rest.length)).fill('0'), ...rest];
  return full.slice(0, 4).map((x) => x.toLowerCase().replace(/^0+(?=.)/, '')).join(':') + '::/64';
}
