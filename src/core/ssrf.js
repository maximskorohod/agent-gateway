// Защита от SSRF (ТЗ §9.1): только доменные имена, резолв перед вызовом, приватные диапазоны отклоняются
import dns from 'node:dns/promises';

// Каноническая запись IPv4: ровно 4 десятичных октета без ведущих нулей, hex и сокращённых форм
function parseIPv4(s) {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n; // 0..2^32-1
}

// IPv6 → массив из 8 групп по 16 бит или null. Скобки и zone id отбрасываются, регистр не важен.
function parseIPv6(input) {
  let s = input.trim().toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const z = s.indexOf('%');
  if (z >= 0) {
    if (z === s.length - 1) return null;
    s = s.slice(0, z);
  }
  if (!s.includes(':') || !/^[0-9a-f:.]+$/.test(s)) return null;
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const toGroups = (part) => {
    if (part === '') return [];
    const items = part.split(':');
    const out = [];
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      if (it.includes('.')) {
        // встроенный IPv4 допустим только последним элементом
        if (i !== items.length - 1) return null;
        const v4 = parseIPv4(it);
        if (v4 === null) return null;
        out.push(Math.floor(v4 / 65536), v4 % 65536);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(it)) return null;
        out.push(parseInt(it, 16));
      }
    }
    return out;
  };
  const head = toGroups(halves[0]);
  if (!head) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  const tail = toGroups(halves[1]);
  if (!tail) return null;
  // «::» заменяет минимум одну группу
  const fill = 8 - head.length - tail.length;
  if (fill < 1) return null;
  return [...head, ...new Array(fill).fill(0), ...tail];
}

// [сеть как 32-битное число, длина префикса]
const v4 = (a, b, c, d, len) => [(((a * 256 + b) * 256 + c) * 256 + d), len];
const V4_NON_PUBLIC = [
  v4(0, 0, 0, 0, 8), v4(10, 0, 0, 0, 8), v4(100, 64, 0, 0, 10), v4(127, 0, 0, 0, 8), v4(169, 254, 0, 0, 16),
  v4(172, 16, 0, 0, 12), v4(192, 0, 0, 0, 24), v4(192, 0, 2, 0, 24), v4(192, 88, 99, 0, 24), v4(192, 168, 0, 0, 16),
  v4(198, 18, 0, 0, 15), v4(198, 51, 100, 0, 24), v4(203, 0, 113, 0, 24), v4(224, 0, 0, 0, 4), v4(240, 0, 0, 0, 4),
  v4(255, 255, 255, 255, 32),
];

function v4NonPublic(n) {
  return V4_NON_PUBLIC.some(([net4, len]) => Math.floor(n / 2 ** (32 - len)) === Math.floor(net4 / 2 ** (32 - len)));
}

// IPv6 как BigInt; [сеть, длина префикса]
const toBig = (g) => g.reduce((acc, x) => (acc << 16n) | BigInt(x), 0n);
const v6 = (groups, len) => [toBig([...groups, ...new Array(8 - groups.length).fill(0)]), len];
const V6_NON_PUBLIC = [
  v6([0x2001, 0x0db8], 32), // документация
  v6([0x2001, 0], 32), // Teredo
  v6([0x2001, 0x10], 28), // ORCHID
  v6([0x2001, 0x20], 28), // ORCHIDv2
  v6([0x2002], 16), // 6to4
  v6([0x3fff], 20), // новая документация
];
const V6_GLOBAL = v6([0x2000], 3);

function inV6(big, [net6, len]) {
  const shift = BigInt(128 - len);
  return big >> shift === net6 >> shift;
}

/** true, если адрес не публичный или не разобран (fail closed) */
export function isPrivateIp(ip) {
  if (typeof ip !== 'string' || !ip) return true;
  if (!ip.includes(':')) {
    const n = parseIPv4(ip.trim());
    return n === null ? true : v4NonPublic(n);
  }
  const g = parseIPv6(ip);
  if (!g) return true;
  // IPv4-mapped ::ffff:0:0/96 — оцениваем как вложенный IPv4 (записи ::ffff:8.8.8.8 и ::ffff:808:808 дают один ответ)
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return v4NonPublic(g[6] * 65536 + g[7]);
  // IPv4-compatible ::/96 (устарел, включает :: и ::1), NAT64 64:ff9b::/96 и 64:ff9b:1::/48 — всегда закрыты:
  // даже NAT64 к публичному IPv4 не пропускаем (fail closed), шлюзу такие адреса не нужны.
  // Это покрывается условием «вне 2000::/3» ниже.
  const big = toBig(g);
  if (!inV6(big, V6_GLOBAL)) return true;
  return V6_NON_PUBLIC.some((r) => inV6(big, r));
}

/**
 * Резолвит имя и возвращает первый публичный адрес; бросает (code EPRIVATE), если хоть один адрес приватный.
 * Нужна вне прокси: Slack-вебхук, демо, bitrix24-box (docs/contracts/rest-demo-notify.md).
 */
export async function resolvePublic(host) {
  const addrs = await dns.lookup(host, { all: true, verbatim: true });
  if (!addrs.length) throw new Error('DNS: no address found');
  for (const a of addrs) {
    if (isPrivateIp(a.address)) throw Object.assign(new Error('service address points to a private network'), { code: 'EPRIVATE' });
  }
  return addrs.find((a) => a.family === 4)?.address || addrs[0].address;
}

export function validateAgentPath(p) {
  if (typeof p !== 'string' || p.length > 2048) return false;
  if (/[\x00-\x1f\x7f]/.test(p)) return false;
  if (p.includes('..') || p.includes('@') || p.includes('://') || p.includes('\\')) return false;
  if (p.startsWith('//')) return false;
  // «#» undici отрезает как фрагмент (сервис получит другой путь, чем видел фильтр), «?» внутри пути — граница query (9.1a)
  if (p.includes('#') || p.includes('?')) return false;
  // сегменты «.» и пустые сегменты сервис схлопнет, а проверки шлюза — нет (П-1)
  const segs = p.replace(/^\//, '').split('/');
  if (segs.some((s, i) => s === '.' || (s === '' && i < segs.length - 1))) return false;
  return true;
}
