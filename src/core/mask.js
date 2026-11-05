// Маскировка персональных данных в значениях строк JSON-ответа (ТЗ §9.3, contracts/rest-demo-notify.md «Маскировка»).
// Четыре прохода по строке в порядке: карта → IBAN → e-mail → телефон. Каждый проход линейный: символы разбираются
// по кодам, без RegExp и без откатов; кандидат, не прошедший проверку, повторно не просматривается.
// Ключи JSON и числа не трогаются; ФИО без ML не ловится (оговорка в интерфейсе).

export const MASK = '****';

const isDigit = (c) => c >= 48 && c <= 57;
const isUpper = (c) => c >= 65 && c <= 90;
const isLower = (c) => c >= 97 && c <= 122;
const isAlnum = (c) => isDigit(c) || isUpper(c) || isLower(c);

/** Сборка результата из непересекающихся отрезков [from, to) по возрастанию; n — число замен. */
function splice(s, spans) {
  if (!spans.length) return { text: s, n: 0 };
  let out = '';
  let pos = 0;
  for (const [a, b] of spans) { out += s.slice(pos, a) + MASK; pos = b; }
  return { text: out + s.slice(pos), n: spans.length };
}

/** Luhn по цифрам отрезка [a, b) строки (нецифры пропускаются). */
function luhnOk(s, a, b) {
  let sum = 0; let alt = false;
  for (let i = b - 1; i >= a; i--) {
    const c = s.charCodeAt(i);
    if (!isDigit(c)) continue;
    let d = c - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}

/** Карта: цифры с одиночными пробелами и дефисами между ними, 13–19 цифр, Luhn. */
function cardSpans(s) {
  const spans = [];
  const n = s.length;
  let i = 0;
  while (i < n) {
    if (!isDigit(s.charCodeAt(i))) { i++; continue; }
    let j = i; let digits = 0;
    while (j < n) {
      const c = s.charCodeAt(j);
      if (isDigit(c)) { digits++; j++; }
      else if ((c === 32 || c === 45) && j + 1 < n && isDigit(s.charCodeAt(j + 1))) j++; // разделитель между цифрами
      else break;
    }
    // Голая строка цифр без разделителей — карта, только если начинается с 2–6: метки времени unix (13 цифр, «1…») и
    // подобные ID с Luhn-совпадением в 10 % случаев картой не считаются. С пробелами и дефисами проверяется любая группа.
    const bare = j - i === digits;
    const first = s.charCodeAt(i);
    if (digits >= 13 && digits <= 19 && (!bare || (first >= 50 && first <= 54)) && luhnOk(s, i, j)) spans.push([i, j]);
    i = j;
  }
  return spans;
}

/** mod-97 для строки IBAN в нормализованном виде (без пробелов, 4 первых символа уже в конце). */
function mod97(chars) {
  let r = 0;
  for (let i = 0; i < chars.length; i++) {
    const c = chars.charCodeAt(i);
    if (isDigit(c)) r = (r * 10 + (c - 48)) % 97;
    else r = (r * 100 + (c - 55)) % 97; // A=10 … Z=35
  }
  return r;
}

const isIbanChar = (c) => isDigit(c) || isUpper(c);

/** IBAN: [A-Z]{2}\d{2} + 11–30 символов, пробелы группами по 4, mod-97; слева и справа не буква и не цифра. */
function ibanSpans(s) {
  const spans = [];
  const n = s.length;
  let i = 0;
  while (i + 15 <= n) {
    if (isUpper(s.charCodeAt(i)) && isUpper(s.charCodeAt(i + 1)) && isDigit(s.charCodeAt(i + 2)) && isDigit(s.charCodeAt(i + 3))
      && (i === 0 || !isAlnum(s.charCodeAt(i - 1)))) {
      let j = i; let compact = '';
      if (s.charCodeAt(i + 4) === 32) {
        // группы по 4 через одиночный пробел, последняя группа 1–4 символа
        while (j < n && compact.length < 34) {
          let g = 0;
          while (j < n && g < 4 && isIbanChar(s.charCodeAt(j))) { compact += s[j]; j++; g++; }
          if (g === 4 && j + 1 < n && s.charCodeAt(j) === 32 && isIbanChar(s.charCodeAt(j + 1))) j++;
          else break;
        }
      } else {
        while (j < n && compact.length < 34 && isIbanChar(s.charCodeAt(j))) { compact += s[j]; j++; }
      }
      if (compact.length >= 15 && compact.length <= 34 && (j >= n || !isAlnum(s.charCodeAt(j))) && mod97(compact.slice(4) + compact.slice(0, 4)) === 1) {
        spans.push([i, j]); i = j; continue;
      }
    }
    i++;
  }
  return spans;
}

const isLocal = (c) => isAlnum(c) || c === 46 || c === 95 || c === 37 || c === 43 || c === 45; // . _ % + -
const isDomain = (c) => isAlnum(c) || c === 46 || c === 45;

/** E-mail: от каждого «@» влево ≤ 64 символов локальной части, вправо ≤ 255 доменных до последней метки из ≥ 2 букв. */
function emailSpans(s) {
  const spans = [];
  const n = s.length;
  let floor = 0; // не заходим на уже найденный отрезок
  let at = s.indexOf('@');
  while (at >= 0) {
    let a = at;
    while (a > floor && at - a < 64 && isLocal(s.charCodeAt(a - 1))) a--;
    let e = at + 1;
    while (e < n && e - at - 1 < 255 && isDomain(s.charCodeAt(e))) e++;
    // хвостовые точки и дефисы — не часть адреса («пишите a@b.com.»)
    while (e > at + 1 && (s.charCodeAt(e - 1) === 46 || s.charCodeAt(e - 1) === 45)) e--;
    if (a < at && e > at + 1) {
      let d = e - 1; // последняя метка домена
      while (d > at && (isLower(s.charCodeAt(d)) || isUpper(s.charCodeAt(d)))) d--;
      if (s.charCodeAt(d) === 46 && e - d - 1 >= 2 && d > at + 1) { spans.push([a, e]); floor = e; at = s.indexOf('@', e); continue; }
    }
    at = s.indexOf('@', at + 1);
  }
  return spans;
}

const isPhoneSep = (c) => c === 32 || c === 40 || c === 41 || c === 45 || c === 46; // пробел ( ) - .

/**
 * Телефон: необязательный «+», цифры с разделителями ( ) - . пробел, 10–15 цифр. Строка цифр без «+» и без
 * разделителей (ID, время unix, суммы) не маскируется. Кандидат — максимальная серия таких символов:
 * разделители подряд не длиннее трёх, иначе серия обрывается. Кандидат из «ГГГГ-ММ-ДД…» и одиночное «.» (десятичная
 * дробь) телефоном не считаются; рядом с «:» (время) тоже.
 */
function phoneSpans(s) {
  const spans = [];
  const n = s.length;
  let i = 0;
  while (i < n) {
    const c0 = s.charCodeAt(i);
    if (!(isDigit(c0) || c0 === 43 || c0 === 40)) { i++; continue; }
    // начало кандидата: «+», «(» или цифра; дальше цифры и разделители
    let j = i; let digits = 0; let seps = 0; let plus = false; let sepRun = 0; let lastDigit = -1; let dots = 0;
    if (c0 === 43) { plus = true; j++; }
    while (j < n) {
      const c = s.charCodeAt(j);
      if (isDigit(c)) { digits++; lastDigit = j; sepRun = 0; j++; }
      else if (isPhoneSep(c) && sepRun < 3 && digits > 0 || (isPhoneSep(c) && c === 40 && digits === 0)) { seps++; sepRun++; if (c === 46) dots++; j++; }
      else break;
    }
    if (digits === 0) { i = Math.max(j, i + 1); continue; }
    // конец отрезка — последняя цифра или закрывающая скобка
    let end = lastDigit + 1;
    if (end < j && s.charCodeAt(end) === 41) end++;
    const prev = i > 0 ? s.charCodeAt(i - 1) : 0;
    const next = end < n ? s.charCodeAt(end) : 0;
    const bare = !plus && seps === 0;
    const isDate = !plus && digits >= 8 && /^\d{4}-\d{2}-\d{2}/.test(s.slice(i, i + 10));
    const decimal = !plus && dots === 1 && seps === 1;
    if (digits >= 10 && digits <= 15 && !bare && !isDate && !decimal && prev !== 58 && next !== 58 && !isAlnum(prev)) spans.push([i, end]);
    i = Math.max(end, i + 1);
  }
  return spans;
}

/** Маскирует одну строку. -> { text, n } (n — число замен). */
export function maskText(input) {
  let s = String(input);
  if (s.length < 6) return { text: s, n: 0 };
  let total = 0;
  const run = (fn) => { const r = splice(s, fn(s)); s = r.text; total += r.n; };
  run(cardSpans);
  run(ibanSpans);
  if (s.includes('@')) run(emailSpans);
  run(phoneSpans);
  return { text: s, n: total };
}

/**
 * Маскирует все строковые значения JSON; ключи, числа, булевы и null остаются. Глубина уже ограничена
 * проверкой checkJsonDepth в прокси; здесь запасной предел — глубже не заходим, значение вырезается.
 * @returns {{ json: any, n: number }}
 */
export function maskJson(value, limit = 64) {
  let n = 0;
  const walk = (v, depth) => {
    if (typeof v === 'string') { const r = maskText(v); n += r.n; return r.text; }
    if (!v || typeof v !== 'object') return v;
    if (depth >= limit) return MASK;
    if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
    // defineProperty: ключ "__proto__" из ответа остаётся обычным полем
    const out = {};
    for (const [k, x] of Object.entries(v)) Object.defineProperty(out, k, { value: walk(x, depth + 1), enumerable: true, writable: true, configurable: true });
    return out;
  };
  const json = walk(value, 0);
  return { json, n };
}
