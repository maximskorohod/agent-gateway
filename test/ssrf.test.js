// Тесты isPrivateIp (П-29): каноничный разбор IPv4/IPv6 и CIDR-таблицы. Сеть не нужна.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPrivateIp } from '../src/core/ssrf.js';

test('IPv4-mapped: обе записи дают один ответ', () => {
  assert.equal(isPrivateIp('::ffff:8.8.8.8'), false);
  assert.equal(isPrivateIp('::ffff:808:808'), false);
  assert.equal(isPrivateIp('::FFFF:0808:0808'), false);
  assert.equal(isPrivateIp('::ffff:7f00:1'), true);
  assert.equal(isPrivateIp('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateIp('0:0:0:0:0:ffff:a00:1'), true);
  assert.equal(isPrivateIp('::ffff:203.0.113.5'), true);
});

test('IPv6: закрытые диапазоны', () => {
  for (const a of ['[::1]', '::1', '::', 'fe80::1%eth0', 'fc00::1', 'ff02::1', '2001:db8::1', '3fff::1', '3fff:fff::1', '2002:c0a8::1',
    '2001:0:4136:e378::1', '2001:10::1', '2001:2f::1', '2001:20::1', '64:ff9b::808:808', '64:ff9b::8.8.8.8', '64:ff9b:1::1', '::8.8.8.8', '::808:808']) {
    assert.equal(isPrivateIp(a), true, a);
  }
});

test('IPv6: публичные', () => {
  for (const a of ['2606:4700:4700::1111', '2a00:1450:4001::1', '[2606:4700:4700::1111]', '2001:4860:4860::8888', '2001:30::1']) {
    assert.equal(isPrivateIp(a), false, a);
  }
});

test('IPv4: служебные и документационные диапазоны', () => {
  for (const a of ['0.0.0.0', '10.1.2.3', '100.64.0.1', '100.127.255.255', '127.0.0.1', '169.254.169.254', '172.16.0.1', '172.31.255.255', '192.0.0.1',
    '192.0.2.1', '192.88.99.1', '192.168.1.1', '198.18.0.1', '198.19.255.255', '198.51.100.7', '203.0.113.9', '224.0.0.1', '240.0.0.1', '255.255.255.255']) {
    assert.equal(isPrivateIp(a), true, a);
  }
  for (const a of ['8.8.8.8', '1.1.1.1', '100.63.255.255', '100.128.0.1', '172.15.255.255', '172.32.0.1', '198.17.255.255', '198.20.0.1', '192.0.3.1', '203.0.114.1']) {
    assert.equal(isPrivateIp(a), false, a);
  }
});

test('мусор и неканоничные формы закрыты', () => {
  for (const a of ['', ' ', 'abc', 'localhost', '1::2::3', ':::', '::ffff:1.2.3', '::ffff:1.2.3.4.5', '::ffff:256.1.1.1', '::ffff:01.2.3.4',
    '1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7::8', 'g::1', '::1%', '0x7f.1', '0177.0.0.1', '127.1', '1.2.3', '1.2.3.4.5', '1.2.3.256', '08.8.8.8',
    '2130706433', '8.8.8.8/32', '1.2.3.4:80', null, undefined, 42, {}]) {
    assert.equal(isPrivateIp(a), true, String(a));
  }
});
