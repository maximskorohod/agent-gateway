# Контракты C: REST-фильтр, защита для всех сервисов, демо, уведомления, каталог

Черновик контрактов (без кода) для `docs/ARCHITECTURE.md`: REST-фильтр, защита для всех сервисов, демо-режим, уведомления, каталог. Стиль и имена — как в ARCHITECTURE.md. Живая проверка форматов ответов HubSpot/Pipedrive/Zendesk ещё не сделана: поля в примерах иллюстративные.

---

## Правила фильтра для REST (П-17)

### Что меняется

Сегодня правило = нормализованный путь (`crm.deal.list`), метод HTTP не смотрится. Для REST правило = **HTTP-метод + маршрут**. Для Bitrix24 всё остаётся как есть.

```js
/** @typedef {{ style?:'rpc'|'rest',           // по умолчанию 'rpc' (Bitrix24 как сейчас)
 *   methodAgnostic?:boolean,                  // rpc: HTTP-метод не участвует в правилах (Bitrix24: GET и POST равнозначны); у style:'rest' всегда false
 *   keep:string[], keepMaxLen?:number,        // служебные поля; только скаляры, длина строки ≤ keepMaxLen (по умолчанию 256) — П-27
 *   deny:string[],                            // rpc: шаблоны метода; rest: 'ANY /маршрут/**' (любой HTTP-метод) или 'POST /маршрут'
 *   denyQuery?:string[],                      // rest: имена query-параметров, закрытых всегда (associations, propertiesWithHistory); 400 `query_not_allowed`
 *   selectParam?:string, selectFor?:string[], selectFormat?:'repeat[]'|'comma',  // 'comma' — HubSpot ?properties=a,b; 'repeat[]' — Bitrix24 select[]=a
 *   readMethods?:string[],                    // rpc: методы чтения для режима readOnly (см. «Защита для всех сервисов»)
 *   entities:Record<string,Entity> }} ProviderFilter */
/** @typedef {{ name:string,
 *   methods?:string[],                        // style:'rpc'
 *   routes?:string[],                         // style:'rest': 'GET /crm/v3/objects/deals/:id'; метод обязателен
 *   extras?:Record<'search'|'batch'|'export', {label:string, routes:string[]}>,  // явные флаги, см. ниже
 *   fields:{path?:string, paths?:string[], label:string, object?:true}[],       // paths — несколько форм ответа (список и одиночный)
 *   defaults:string[] }} Entity */
/** @typedef {{ enabled:boolean, entities:Record<string,string[]>, flags:Record<string,string[]>, // flags[entityId] = ['search'], по умолчанию []
 *   methods:string[], fields:string[], readOnly:boolean, mask:boolean }} DataFilter  // flags, readOnly, mask — новые; старые записи читаются normalizeFilter как []/false */
```

### Синтаксис маршрута

`ШАБЛОН = [МЕТОД ' '] СЕГМЕНТ{'/'СЕГМЕНТ}`. Сегмент: литерал, `:имя` (ровно один непустой сегмент), `*` (ровно один непустой сегмент; только в ручных правилах владельца и в deny), `**` (остаток пути любой глубины; **только последним сегментом и только в deny**).

- `:id` и `*` не пересекают `/`. Значение сегмента: `[A-Za-z0-9_.~-]{1,128}`, не «.» и не «..»; иначе не совпало.
- Литералы сравниваются без учёта регистра, значения `:id` как есть. Один хвостовой `/` отбрасывается.
- Query в маршруте не участвует. Путь агента уже прошёл `validateAgentPath` и `plainPath` (без `%`, `.`, пустых сегментов).
- Метод: `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`. `HEAD` совпадает с правилом `GET`. `OPTIONS`, `TRACE`, `CONNECT` — всегда отказ.

### Матчер (линейный, П-28)

Шаблон компилируется один раз в массив `[{t:'lit'|'param'|'star'|'rest', v}]`, путь режется по `/` один раз; сравнение идёт слева направо одним проходом. Откатов нет: `**` только в конце, жадного «съедания» с возвратом не бывает. Регулярные выражения для маршрутов не используются. Для rpc-стиля старый `globRe` (`*` → `.*`, backtracking) заменяется линейным сопоставлением со `*` по алгоритму «две позиции + запомненная последняя звезда»; шаблонов с более чем двумя звёздами каталог и форма не принимают.

Лимиты (проверяют `loadCatalog` и `checkFilter` при сохранении; при выполнении — отказ):

| Что | Лимит |
|---|---|
| Правил в скомпилированном фильтре (каталог + ручные) | ≤ 64 |
| Сегментов в шаблоне и в пути | ≤ 12; путь длиннее не совпадает |
| Длина шаблона | ≤ 200 |
| Звёзд `*` в одном rpc-шаблоне | ≤ 2 |
| Полей в типе / путей в ручном правиле | ≤ 200 |
| Глубина JSON ответа | ≤ 32, глубже — 502 `filtered_too_deep` |
| Глубина пути поля | ≤ 8 |

Глубину считают до `JSON.parse` линейным проходом по байтам (скобки вне строк); `prune` тоже получает счётчик глубины и останавливается на 33-м уровне.

### Контракт compileFilter

```js
compileFilter(filter, provider) // -> null | {
//   allowMethod(httpMethod, path) -> bool   // ИЗМЕНЕНО: добавлен httpMethod. Порядок: plainPath → deny (любой метод) → readOnly/запись → правила (тип, флаги, ручное)
//   denyReason(httpMethod, path) -> 'method_not_allowed'|'write_not_allowed'|null   // для 403 и audit
//   checkQuery(httpMethod, path, query) -> null | 'query_not_allowed' | 'hidden_field_filter'  // denyQuery из каталога; hidden_field_filter — хук П-18, в 1.0 возвращает null
//   rewriteSelect(...)  // как раньше; selectFormat 'comma' для HubSpot: ?properties=<поля через запятую>, все другие формы properties/properties[] удаляются
//   filterBody(json, path, httpMethod) -> {json, removed, masked}
//   methods:string[]                         // для подсказки агенту: 'GET /crm/v3/objects/deals/:id' (rest) или 'crm.deal.get' (rpc)
// }
```
`methodAgnostic`: `allowMethod` игнорирует `httpMethod` при сопоставлении с `methods`, но режим `readOnly` его учитывает (ниже). Прокси передаёт `req.method` всегда.

### Запись, search, batch, export

- Метод записи = `POST|PUT|PATCH|DELETE`. Тип данных (read entity) **никогда** не открывает запись: маршрут с методом записи в `routes` без `extras` — ошибка загрузки каталога; ручное правило владельца с методом записи — ошибка `checkFilter` (фильтр на запись вне релиза, ТЗ §9.4).
- `search`, `batch`, `export` описываются в `entity.extras` с явными маршрутами. HubSpot `POST /crm/v3/objects/deals/search` — POST, но читает; открывается только если у владельца отмечен флаг `flags.deals = ['search']`. Без флага — 403.
- В 1.0 для HubSpot/Pipedrive/Zendesk `extras` содержит только `search` (HubSpot, Zendesk `/api/v2/search.json`); batch и export остаются в `deny`.
- Любой флаг = ослабление (`weakensFilter`: новый флаг → свежий 2FA), снятие — ужесточение. В `normalizeFilter` флаги без существующего `extras` отбрасываются.
- Тело search-запроса агента в 1.0 не разбирается (ограничение П-18 ниже).

### Поля ответа (REST JSON)

- Пути через точку, массивы проходятся насквозь: `results[].properties.dealstage`; `[]` необязателен, нужен для читаемости. Несколько форм одного поля — `paths: [results[].properties.dealstage, properties.dealstage]` (список и одиночный объект).
- Поле без `object: true` проходит **только если значение скаляр** (строка, число, boolean, null); строка длиннее `maxFieldLen` (по умолчанию 4000) обрезается до лимита, `removed`+1. Объект или массив под таким путём вырезается целиком. `object: true` в каталоге разрешает поле-контейнер (например, PHONE Bitrix24 с массивом объектов) — это сегодняшнее поведение узла `true`.
- `keep` — всегда «только скаляр, длина ≤ `keepMaxLen`» (П-27). У Bitrix24 `keep` сейчас содержит `time` и `error_description`: `time` объект и начнёт вырезаться; если нужен — перечислить `time.start`, `time.finish` (проверить живьём).
- Для Bitrix24 `object: true` проставляется в yaml у PHONE/EMAIL одним коммитом с кодом.

### Пример: HubSpot (поля иллюстративные; живая проверка ответов не выполнена, `defaults` и `selectFor` могут измениться)

Поправка 7.1: в реальном yaml пути с `[]` внутри flow-списков берутся в кавычки (`paths: ['results[].id', 'id']`, так же `defaults`), иначе yaml не разбирается. `denyQuery` допустим только при `style: rest`; `methodAgnostic` у rest запрещён; у rest-типа вместо `methods` — `routes`.

```yaml
hubspot:
  name: HubSpot
  host: api.hubapi.com
  injection: { type: header, name: authorization, prefix: 'Bearer ' }
  keyPattern: '^pat-[a-z0-9]+-[a-f0-9-]+$'
  readOnly: { extraRoutes: ['POST /crm/v3/objects/*/search'] }   # см. «Защита для всех сервисов»
  filter:
    style: rest
    keep: [status, message, category, correlationId, total, paging.next.after]   # только скаляры ≤ 256 символов
    deny:
      - ANY /crm/v3/objects/contacts/**
      - ANY /crm/v3/objects/companies/**
      - ANY /crm/v3/objects/*/batch/**
      - ANY /crm/v3/exports/**
      - ANY /crm/v4/associations/**
      - ANY /crm/v3/owners/**
      - ANY /crm/v3/imports/**
    denyQuery: [associations, propertiesWithHistory, archived]
    selectParam: properties
    selectFormat: comma
    selectFor: ['GET /crm/v3/objects/deals']      # у одиночной сделки набор по умолчанию режется prune
    entities:
      deals:
        name: Deals without contacts
        routes:
          - GET /crm/v3/objects/deals
          - GET /crm/v3/objects/deals/:id
        extras:
          search:
            label: Search deals          # POST читает, но поиск по скрытым полям — П-18
            routes: [POST /crm/v3/objects/deals/search]
        fields:
          - { paths: [results[].id, id], label: ID }
          - { paths: [results[].properties.dealname, properties.dealname], label: Title }
          - { paths: [results[].properties.dealstage, properties.dealstage], label: Stage }
          - { paths: [results[].properties.pipeline, properties.pipeline], label: Pipeline }
          - { paths: [results[].properties.amount, properties.amount], label: Amount }
          - { paths: [results[].properties.hubspot_owner_id, properties.hubspot_owner_id], label: Owner (ID) }
          - { paths: [results[].properties.createdate, properties.createdate], label: Created }
          - { paths: [results[].properties.hs_lastmodifieddate, properties.hs_lastmodifieddate], label: Modified }
        defaults: [results[].id, id, results[].properties.dealstage, properties.dealstage, results[].properties.createdate, properties.createdate]
```
`associations` (контакты сделки) не перечислены → вырезаются prune; параметр `associations` закрыт `denyQuery`.

Pipedrive: `GET /v1/deals`, `GET /v1/deals/:id`, `GET /api/v2/deals…`, deny `/v1/persons/**`, `/v1/organizations/**`, `/v1/activities/**`, `/v1/notes/**`; поля `data[].id|title|status|stage_id|value|currency|user_id|add_time|update_time`. `person_id` приходит объектом `{name, email[], phone[]}`: **без** `object:true` вырезается целиком (если нужен ID, отдельное поле `person_id.value`, проверить живьём). Zendesk: `GET /api/v2/tickets`, `GET /api/v2/tickets/:id`, deny `/api/v2/users/**`, `/api/v2/organizations/**`; `requester_id` остаётся (скаляр); `subject`/`description` — отдельные поля, по умолчанию не отмечены.

### Ограничение П-18 и хук

Агент с разрешёнными методами может искать по скрытому полю (Pipedrive `?filter_id=`, Bitrix24 `filter[PHONE]=…`, HubSpot search `filterGroups[].propertyName=email`) и по числу и порядку результатов узнавать, есть ли совпадение. В SECURITY.md — известное ограничение 1.0. Хук этапа B: `checkQuery(method, path, query)` для маршрутов из `selectFor` отклоняет query, где имя параметра `filter[...]`/`sort`/`order` содержит имя поля вне разрешённых (`hidden_field_filter`, 403, audit `proxy.denied`); для `extras.search` — разбор тела `filterGroups` и `sorts` по тому же правилу. В 1.0 функция существует, возвращает `null`, покрыта тестом-заглушкой.

---

## Защита для всех сервисов

Решение владельца: слой 1 действует у **любого** провайдера и входит в тот же `DataFilter` (поля `readOnly`, `mask`), а не требует «типов данных». Включённый только `readOnly` или `mask` при `enabled:false` (нет галочек полей) означает: методы и поля не фильтруются, работают только эти два режима.

```js
compileFilter(filter, provider) // -> null только если !enabled && !readOnly && !mask
// добавляется в результат: { readOnly:boolean, mask:boolean, needsBuffer:boolean }  // needsBuffer = enabled || mask
```

### Только чтение (readOnly)

- REST-провайдер (HubSpot, Pipedrive, Zendesk, GitHub, Notion, amoCRM, Stripe, «Другой»): разрешены **только** `GET` и `HEAD`. Остальное → 403 `write_not_allowed`, лимит не тратится, audit `proxy.denied`.
- POST-чтение (поиск): каталог перечисляет в `readOnly.extraRoutes: ['POST /crm/v3/objects/*/search']`; такие маршруты проходят в режиме readOnly (если не закрыты deny).
- RPC-провайдер (Bitrix24, Telegram): только методы из `provider.filter.readMethods` (шаблоны, ≤ 2 звёзд). Bitrix24: `[crm.*.list, crm.*.get, crm.*.fields, user.get, user.fields]`; Telegram: `[getMe, getChat, getChatMemberCount, getChatAdministrators]`; `getUpdates` исключён (сдвигает очередь).
- Провайдеры, где запись неотличима от чтения (OpenAI, Anthropic, Gemini, Groq, Mistral, OpenRouter, Resend, SendGrid, Twilio, Linear GraphQL, ElevenLabs, Deepgram): в каталоге `readOnly: false`, чекбокс скрыт. «Другой»: GET/HEAD.
- readOnly сильнее типов данных: метод записи не откроет даже ручное правило.
- Выключение `readOnly` — ослабление (свежий 2FA в `weakensFilter`), включение — без кода.

### Маскировка (mask)

Применяется к **значениям строк** любого JSON-ответа, включая `keep` и разрешённые поля; ключи и числа не трогаются. Замена — `****` на весь найденный фрагмент. Без ML; ФИО не ловится (оговорка в интерфейсе, ТЗ §9.3).

| Что | Правило (линейный сканер, без backtracking) |
|---|---|
| E-mail | от каждого `@` расширение влево по `[A-Za-z0-9._%+-]` (≤ 64) и вправо по `[A-Za-z0-9.-]` (≤ 255) до точки с TLD ≥ 2 букв |
| Карта | цифры с одиночными пробелами/дефисами, 13–19 цифр, проверка Luhn |
| IBAN | `[A-Z]{2}\d{2}` + 11–30 буквенно-цифровых, пробелы группами по 4, проверка mod-97 |
| Телефон | необязательный `+`, цифры с разделителями `[ ()\-.]`, без `:`; 10–15 цифр; **голая строка цифр без `+` и без разделителей не маскируется** (ID, unix-время, суммы) |

Кандидат в телефон, начинающийся с `YYYY-MM-DD`, не маскируется. Порядок: карта → IBAN → e-mail → телефон. Не-JSON ответ при `mask` → 502 `filtered_non_json`, `text/event-stream` → 502 `filtered_stream`.

### Место в порядке прокси и цена

Порядок `createProxy.handle` (заменяет абзац в ARCHITECTURE.md):

1. `validateAgentPath` (сырой и декодированный).
2. `flt.allowMethod(req.method, decodedPath)`: deny → readOnly/запись → правила и флаги → 403 `method_not_allowed` | `write_not_allowed`; `flt.checkQuery` → 400 `query_not_allowed`. Лимит не тратится.
3. `reserve` (429).
4. `resolvePublic(host)`, сборка URL, `rewriteSelect`, upstream с `Accept-Encoding: identity`.
5. `Content-Encoding` ≠ identity → 502 `upstream_encoded`.
6. Если `needsBuffer`: чтение целиком в пределах `min(maxBody, bufferMax)` (`bufferMax` по умолчанию 8 MiB; больше → 502 `filtered_too_large`) → проверка глубины → `JSON.parse` → `filterBody` (prune, затем mask) → `redactText(JSON.stringify(...), secrets)` → отправка с новым `content-length`; `etag`, `content-md5`, `content-length` апстрима убираются.
7. Иначе (только `readOnly` или фильтр выключен) — поток через redactor, как сейчас.
8. Audit: `fields_removed:N`, `masked:N` (только числа), `denied_reason`.

Цена: при `mask` или фильтре полей ответ целиком в памяти (до 8 MiB × `max_parallel`), нет потока и SSE, добавляется `JSON.parse` и проход по строкам, O(размер). `readOnly` — ничего сверх проверки метода. Для Deepgram (200 MiB) и LLM-провайдеров `mask: false` в каталоге.

---

## Демо-режим (П-20)

`GW_DEMO=1`. Цель: публичный экземпляр, на котором **физически** нет реальных данных и нет исходящих соединений. Слои: запуск, транспорт, allowlist запросов, сервер (systemd/nftables).

```js
// config.js: demo:boolean, demoResetSec=3600, waitlistUrl:string
// src/demo/guard.js
export async function assertDemoIsolation({ cfg, db, vault }) // throw Error('demo_isolation: <правило>') → bin/gateway.js выходит с кодом 1 до listen()
export function installNetworkGuard()                         // process-wide, см. «Сеть»
export function demoRouteGuard(fastify, ctx)                  // onRequest-хук, регистрируется ПЕРВЫМ в buildApp, до registerWeb/agentApi/mcp
export function createDemoTransport()                         // замена undici.request в core/proxy.js
export function createDemoMock()                              // встроенный провайдер: handle({method, path, headers, body}) -> {status, headers, body:Readable}
export function createDemoReset({ repo, vault, cfg, logger }) // -> { runOnce(), loop() }
```

### Запуск: отказ при реальных данных

`assertDemoIsolation` вызывается в `buildApp` после `openDb`/`createVault`, до таймеров и `listen`. Отказ, если выполнено любое:

1. `GW_VAULT` ≠ `file` или заданы `AWS_*`/`GW_SSM_*`/`GW_VAULT_PREFIX` (в демо `vault/ssm.js` не импортируется вообще).
2. `GW_DATA_DIR` не задан явно, либо каталог непустой и в нём нет маркера `.demo-data` (создаётся при первом запуске пустого каталога).
3. В сейфе (`vault.names()` — новый необязательный метод file-сейфа) есть имя вне `sys/*` и `cred/demo`; есть `sys/slack_webhook`, `sys/smtp`, `sys/tg*`.
4. В базе любая строка `credentials` (включая удалённые) с `provider ≠ 'demo'`; заполнены `owner.tg_chat_id`/`tg_bot`; в `meta` есть настройки каналов уведомлений; у владельца есть `password_hash`.
5. `GW_PUBLIC_URL` совпадает с хостом из `GW_PROD_HOSTS` (необязательная страховка).

Текст отказа не содержит значений: только имя правила и `cred/<id>`.

### Данные и сброс раз в час

- Каталог в демо: `loadCatalog` отдаёт **только** провайдера `demo` (в `providers.yaml` с `demoOnly: true`, вне демо скрыт). Host `demo.invalid` (зарезервированный TLD), `fields: [key]`, фиксированный `keyPattern` (`demo-…`), фильтр с типами «Deals»/«Contacts» для показа фильтра и маскировки.
- Сид: владелец без пароля, ключ `cred/demo`, агент `demo-agent`; «Simulate agent request» создаёт заявку через настоящий `requests.submit`.
- `runOnce()`: флаг `resetting` (запросы → 503 `demo_resetting`, до 2 с), `revokeAllGrants`, транзакционная очистка **всех** таблиц (`repo.demoWipe()`, существует только при `cfg.demo`), перезапись `vault.json`, сид заново, `meta.demo_reset_at`. Цикл: `setInterval(30 с)`, сброс при `unixepoch() - demo_reset_at ≥ demoResetSec`; на старте всегда сброс. `reapLoop`/`expireLoop` продолжают работать.

### Сеть: исходящих соединений нет

- `createProxy({ ..., transport })`; в демо `transport = createDemoTransport()`: хост `demo.invalid` → `mock.handle` в процессе (без сокетов), любой другой хост → `demo_network_disabled`. `resolvePublic` для `demo.invalid` не вызывается.
- `installNetworkGuard()` (вторая линия): обёртка `net.Socket.prototype.connect` и `dns.lookup`/`dns.promises`: любое исходящее соединение (и loopback тоже, шлюз ни к кому не ходит) → `demo_network_disabled`; `undici.setGlobalDispatcher` на агент, чей `connect` бросает то же. Входящий `listen` не затронут.
- Не создаются: клиент SSM, Telegram-менеджер (`tg.init()` пропускается, `tg.current()` = null), каналы Slack/Email, проверки обновлений, скачивание иконок.
- Третья линия (docs/DEPLOY.md): systemd `IPAddressDeny=any` + `IPAddressAllow=localhost`, nftables output drop, кроме ответов на установленные входящие.

### Allowlist маршрутов (на сервере, по умолчанию отказ)

`demoRouteGuard` — единственный источник правды: таблица `[метод, шаблон, условие]`; всё вне таблицы → 404 (не 403). Проверка до CSRF и роутера, по реальному пути, а не по скрытым элементам интерфейса.

| Разрешено | Условие |
|---|---|
| `GET /healthz`, `GET /public/*` | — |
| `GET /`, `GET /login` | `/login` в демо = автовход: сессия демо-владельца без пароля и 2FA, редирект на `/` |
| `GET /keys`, `/keys/:id`, `/agents`, `/stats`, `/audit` | только данные демо |
| `POST /keys/:id/policy`, `/filter` | `credential.provider === 'demo'`; `requireRecentTotp` в демо считается выполненным |
| `GET/POST /keys/new/demo` | провайдер строго `demo`, не больше 3 ключей |
| `POST /agents`, `POST /agents/:id/keys` | не больше 5 агентов; имя ≤ 40 символов |
| `POST /requests/:id/approve|deny`, `POST /demo/simulate` | `simulate` — 6/мин на IP |
| `POST /v1/grants`, `GET /v1/grants/:id`, `ANY /v1/proxy/demo/*` | провайдер строго `demo` |
| `/mcp` | инструменты работают на демо-каталоге; `call` с другим сервисом → `unknown_service` |

Закрыто целиком (404): `/setup/*`, `/l/*`, `/totp`, `/settings/*` (включая уведомления и Telegram), `/keys/new/<не demo>`, `POST /keys/:id/delete|replace`, «Выйти везде». Тела запросов в демо ≤ 64 KiB.

- Лимиты по IP (`core/ratelimit.js`, ключ `demo:<класс>:<ip>`): сайт 120/мин, API и MCP 60/мин, simulate 6/мин, заявки 10/мин. IP берётся из `trustProxy`.
- Баннер в `layout()` на каждой странице: «Shared demo. Data resets hourly. Do not enter real data.» + ссылка на лист ожидания. `X-Robots-Tag: noindex`. Демо-ключ публичный; пользовательские поля ограничены (метка ≤ 40, escape).

### Что держится на всех входах

| Вход | Защита |
|---|---|
| REST `/v1/*` | allowlist + каталог из одного провайдера + транспорт-заглушка |
| MCP `/mcp` | allowlist, демо-каталог, `call` идёт через тот же `createProxy` с демо-транспортом |
| Setup `/setup/*`, `/l/*`, `/totp` | 404; мастер не запускается, `setup_done` ставит сид |
| Фоновые циклы | только `reapLoop`, `expireLoop`, `demoReset`; `tg` и каналы уведомлений не стартуют |
| Уведомления | `createNotifier` получает пустой список каналов |

---

## Уведомления и лист ожидания

### Каналы (`notify.js`, §12)

Публичный интерфейс `createNotifier` (`requestCreated`, `requestDecided`, `grantAuto`, `info`) не меняется; добавляется `async idle()` (для тестов) и список каналов.

```js
export function createNotifier({ repo, getBot, vault, logger, channels? /* по умолчанию telegram + slack + email из настроек */ })
/** @typedef {{ event:'request.created'|'request.decided'|'grant.auto'|'key.expired'|'security'|'info',
 *   title:string, text:string, url?:string /* обычная ссылка на сайт, не /open и не one-time */ }} NotifyMessage */
/** @typedef {{ id:'telegram'|'slack'|'email', buttons:boolean,
 *   enabled():boolean,                       // meta `notify.<id>` {enabled, events[]} + секрет в vault
 *   send(msg:NotifyMessage):Promise<void>,   // бросает при сбое; fan-out перехватывает
 *   test():Promise<void> }} Channel */
```
- `telegram` — существующий бот, `buttons:true`: `requestCreated`/`requestDecided` идут через `bot.sendRequest`/`editDecided`, остальные события — `bot.send`.
- `slack` — Incoming Webhook; URL в vault `sys/slack_webhook`; `buttons:false`. Проверки: https, host `hooks.slack.com`, 443, `resolvePublic`, без редиректов, таймаут 10 с. Текст: экранирование `& < >` (нет `<!channel>`), причина заявки ≤ 300 символов.
- `email` — SMTP, настройки в vault `sys/smtp` (`{host, port, user, pass, from, to[]}`); `nodemailer` подключается лениво (`import()` при включённом канале), `requireTLS: true`, порт 587 (STARTTLS) или 465 (implicit TLS), `tls: {rejectUnauthorized:true, minVersion:'TLSv1.2'}`; без шифрования — ошибка при сохранении; хост через `validateOwnerHost` + `resolvePublic`, соединение к проверенному IP с `servername`. Только `text/plain`, без трекинга, CR/LF из subject убираются.
- Fan-out: `Promise.allSettled` по `channels.filter(enabled && events.includes(event))`, у каждого свой таймаут 10 с. Сбой канала → `logger.error({channel, code})`, без `err.message` (webhook-путь секретен) и без текста сообщения. Запрос агента и решение от результата не зависят: вызовы notify из `submit()` не ждут доставки (`void`, учёт в `idle()`).
- В сообщениях нет секретов, `gwa_`/`gwt_` токенов и значений ключей; ссылка — `publicUrl + '/requests'`.

### Какие события куда

| Событие | Telegram | Slack | E-mail |
|---|---|---|---|
| `request.created` | кнопки (как сейчас) | вкл. по умолчанию, без кнопок | выкл. |
| `request.decided` | правка сообщения | вкл. | выкл. |
| `grant.auto` («always») | вкл. | вкл. | выкл. |
| `key.expired` / «always» закончился | вкл. | вкл. | вкл. |
| `security`: новая сессия, смена пароля/2FA, фильтр ослаблен, «выйти везде», новый агент, привязка Telegram | вкл. | вкл. | вкл. |
| `info` | вкл. | вкл. | выкл. |

Настройки → Notifications: каждый канал включается отдельно, включение и смена секрета — свежий 2FA, кнопка «Send test»; события — галочками (`meta notify.<id>.events`). Если Telegram не подключён, а Slack/e-mail включены, заявка с `approval: tg_*` даёт только ссылку на сайт.

### Лист ожидания «Cloud — join the waitlist»

- `config.waitlistUrl = env.GW_WAITLIST_URL`; пусто — ссылка не показывается. Валидация: `https:`, ≤ 300 символов; иначе предупреждение в лог и пусто.
- Показывается: подвал `layout()`, баннер демо, экран «It works», README (подстановка при релизе, не из рантайма). Обычный `<a href rel="noopener noreferrer" target="_blank">`, ключ i18n `cloud.waitlist`. Без скриптов, пикселей и UTM с данными шлюза; `Referrer-Policy: no-referrer` уже стоит; CSP не меняется. Подсчёт откликов — на стороне формы листа ожидания.

---

## Каталог (П-23, П-24)

### П-23: builder по типу провайдера, неизменный фиксированный хост

```js
export function buildInjection(provider, ownerInput) // сигнатура та же; внутри — builders[provider.builder]
// provider.builder: 'static' | 'webhook' | 'subdomain' | 'basic' | 'other'; по умолчанию 'static'; 'other' только у slug other
```
- Выбор по `provider.builder`, **не** по наличию полей: веток `fields.includes(...)` не остаётся.
- Инвариант: если `provider.host !== 'owner'`, результат `host === provider.host` при любом вводе. Поле `account` у фиксированного хоста идёт только в секрет (Basic), не в host. `loadCatalog` падает, если фиксированный хост сочетается с полем `host`/`webhook_url` или с `builder: subdomain`.
- `subdomain`: `host: owner` + `hostTemplate: '{account}.amocrm.ru'` / `'{account}.zendesk.com'`; account — метка DNS `[a-z0-9-]{1,63}` или полный адрес, проверка `hostPattern`.
- `basic` (`encode: base64`): Twilio (`fields:[account,key]`, `accountPattern: ^AC[a-f0-9]{32}$`) и Zendesk (`fields:[account,email,key]`, секрет `email/token:key`). Инъекция `{type:header, name:authorization, prefix:'Basic ', encode:'base64'}`: прокси ставит `prefix + base64(secret)`; в сейфе `account:key`. В `FIELDS` добавляется `email`.
- `catalog.secretForms(provider, secret) -> string[]`: сырая, URL-кодированная и base64-формы (для Basic ещё отдельно ключ); `makeRedactor` получает весь набор (Н-7).
- Pipedrive: `host: api.pipedrive.com`, `injection: {type: header, name: x-api-token}`. В yaml у Twilio убрать комментарий «не работает» после готовности builder.

### П-24: bitrix24 (облако) и bitrix24-box

- `bitrix24`: `hostPattern: '^[a-z0-9-]+\.bitrix24\.(ru|com|by|kz|ua|de|eu)$'` (без альтернативы `^[a-z0-9.-]+$`).
- `bitrix24-box`: `host: owner`, `builder: webhook`, `hostPattern` нет, `warning: true` → на форме ключа предупреждение (`catalog.warn.bitrix24-box`), только https:443 и доменное имя, `resolvePublic` на каждый вызов, `filterFrom: bitrix24` (блок фильтра копируется при загрузке каталога).
- Slug с дефисом проходит `^[a-z][a-z0-9-]*$`; `_` — нет.
- Миграция при старте: `credentials.provider='bitrix24'`, но `host` не подходит под новый шаблон → `provider='bitrix24-box'`, audit `catalog.migrated`; секрет в сейфе не трогается.

---

## Тесты (node:test, без сети и AWS)

**`test/filter-rest.test.js`**
1. `GET /crm/v3/objects/deals` и `/deals/123` разрешены типом `deals`; `/deals/123/associations/contacts` и `/deals/123/456` — нет (`:id` один сегмент).
2. `POST /crm/v3/objects/deals`, `PATCH …/123`, `DELETE …/123` → `write_not_allowed` и при включённом типе, и при ручном `GET /crm/v3/objects/*` (ручное правило с POST — ошибка `checkFilter`).
3. `POST /crm/v3/objects/deals/search`: 403 без `flags.deals=['search']`, разрешён с флагом; новый флаг в `weakensFilter` → true.
4. Ручное `GET /crm/v3/objects/*` не открывает `contacts` и `contacts/123/x` на любой глубине (deny `**`); `**` вне deny — ошибка `checkFilter`.
5. `/crm/v3/objects/deals/./x`, `%2e`, `//` отклоняются (`plainPath`).
6. Регистр: `/CRM/V3/Objects/Deals` совпадает; ID `AbC` не меняется.
7. Bitrix24 не сломан: `methodAgnostic`, `POST /crm.deal.list.json` и `GET /crm.deal.list` оба разрешены; существующие `filter.test.js` и `filter-e2e.test.js` проходят без правок.
8. Лимиты: 65 правил, 13 сегментов, три `*` в rpc-шаблоне, шаблон 201 символ → ошибка загрузки каталога или `checkFilter`.
9. Время: 12-сегментный шаблон против пути `'a/'.repeat(12)+'x'` < 5 мс; rpc-шаблон `a*a*` против 100 000 `a` < 50 мс (регрессия ReDoS, П-28).
10. JSON глубиной 33 → `filtered_too_deep` (502); глубиной 32 проходит; скобки внутри строк не считаются.
11. `results[].properties.dealstage` остаётся; `results[].properties.email`, `associations`, `results[].contacts` вырезаются, `removed` верный; одиночная форма `properties.dealstage` тоже.
12. П-27: поле-объект без `object:true` вырезается; строка 5000 символов обрезается; объект `time` в `keep` вырезается, скаляр `status` остаётся; `object:true` у PHONE Bitrix24 сохраняет массив.
13. `denyQuery`: `?associations=contacts` → 400; `selectFormat:'comma'` подменяет `?properties=email,phone` на разрешённые.
14. П-18: `checkQuery` возвращает `null` (заглушка фиксирует контракт).

**`test/layer1.test.js`**
1. `readOnly` на REST: `GET`/`HEAD` проходят, `POST|PUT|PATCH|DELETE` → 403 `write_not_allowed`, лимит не списан, audit `proxy.denied`.
2. `readOnly` на RPC: `crm.deal.list` проходит, `crm.deal.add`/`crm.deal.update` нет; Telegram `getMe` да, `sendMessage`/`getUpdates` нет.
3. `readOnly` у OpenAI недоступен: сохранение формы с `readOnly:true` → ошибка.
4. Фильтр выключен, `mask:true`: `"+7 (999) 123-45-67"`, `"a.b@c.example"`, `"4111 1111 1111 1111"`, `"DE89 3704 0044 0532 0130 00"` → `****`; `"1699000000123"`, `"2026-11-03 12:00"`, число `1234567890` не тронуты; ключи JSON не меняются.
5. Luhn-невалидные 16 цифр и IBAN с неверным mod-97 не маскируются.
6. Строки из 1 MiB `@@@@…` и `1 1 1 1 …` обрабатываются < 200 мс (линейность).
7. `mask` + не-JSON → 502; `mask` + ответ > `bufferMax` → 502 `filtered_too_large`; `readOnly` без `mask` — ответ идёт потоком (первый чанк до завершения upstream).
8. Секрет в ответе при `mask` всё равно редактируется `redactText` после маскировки.

**`test/demo.test.js`**
1. `assertDemoIsolation`: пустой каталог проходит и создаёт `.demo-data`; `cred/abc` в сейфе → отказ; `credentials.provider='bitrix24'` (в том числе с `deleted_at`) → отказ; `sys/smtp` → отказ; `GW_VAULT=ssm` → отказ; непустой каталог без маркера → отказ; в тексте ошибки нет значений секретов.
2. Сеть: после `installNetworkGuard()` `net.connect(443,'1.1.1.1')`, `fetch('https://example.com')`, `undici.request` → `demo_network_disabled`; `ANY /v1/proxy/demo/ping` отвечает из мока при нуле вызовов `Socket.connect`.
3. Allowlist: `/settings/password`, `/setup/x`, `/l/x`, `/totp`, `POST /keys/:id/delete`, `POST /keys/new/openai` → 404; `POST /keys/<id>/policy` для не-демо ключа → 404; `/v1/proxy/openai/x` → 404; `GET /login` создаёт сессию без пароля.
4. MCP в демо: `list_services` возвращает только `demo`, `call` с `service:'github'` → `unknown_service`.
5. Лимиты: 7-й `simulate` за минуту → 429; шестой агент → отказ.
6. Сброс: после `runOnce()` пусты `audit`, `sessions`, лишние агенты; сид на месте; во время сброса запрос → 503; повторный `assertDemoIsolation` проходит.
7. Фоновые циклы: в демо `tg.current()===null` и `notifier.channels.length===0`.

**`test/notify.test.js`**
1. Три mock-канала: один бросает, один висит 15 с — `submit()` возвращается сразу, остальные доставили, `logger.error` с `channel`, без текста сообщения и URL.
2. Таблица событий: `request.created` идёт в telegram (кнопки) и slack (без), в email — нет по умолчанию.
3. Slack: URL не `hooks.slack.com` или http → ошибка сохранения; `<!channel>` в причине экранирован; причина обрезана до 300.
4. Email: конфиг без TLS отклонён; mock SMTP на localhost без STARTTLS → `send` падает; subject с `\r\n` очищен.
5. Секреты `sys/slack_webhook` и `sys/smtp` не попадают ни в логи, ни в audit (grep по буферу логов).
6. `GW_WAITLIST_URL`: `https://example.org/w` отображается в layout и демо-баннере; `javascript:` и `http:` отбрасываются; на страницах нет `<script>` кроме `/public/*.js` и нет внешних `src`.

**`test/catalog-builders.test.js`**
1. Для каждого провайдера с фиксированным хостом ввод `{account:'evil.com', host:'evil.com', webhook_url:'https://evil.com/rest/1/a/'}` → `host === provider.host`.
2. Twilio: корректный `AC…32hex` + `key` → `Basic base64(AC…:key)`; неверный формат account → ошибка; `secretForms` содержит base64-форму.
3. Zendesk: `account=acme` → `acme.zendesk.com`; `acme.evil.com` отклонён.
4. `loadCatalog` падает на фиксированном хосте с полем `host`.
5. `bitrix24`: `evil.com` отклонён, `x.bitrix24.ru` принят; `bitrix24-box`: произвольный домен принят, `localhost`, IP и порт ≠ 443 отклонены; на форме предупреждение; фильтр совпадает с `bitrix24`.
6. Миграция: ключ `bitrix24` с host `portal.corp.example` → `bitrix24-box` при старте, audit `catalog.migrated`.

---

## Решения (03.11, проверка контракта)

1. `readOnly` по умолчанию **включён** у новых ключей CRM и поддержки (Bitrix24, amoCRM, HubSpot, Pipedrive, Zendesk); у остальных выключен или скрыт. Выключение — свежий 2FA.
2. `mask` для LLM и потоковых провайдеров не предлагается.
3. Голые цифры без `+` не маскируются; это известное ограничение в интерфейсе и SECURITY.md.
4. Поля HubSpot/Pipedrive/Zendesk и `denyQuery` фиксируются только после живой проверки (тестовые аккаунты владельца, этап 7).
5. Демо: один общий демо-владелец, сброс раз в час.
6. MCP на демо включён (это витрина), только демо-каталог и лимиты по IP.
7. `vault.names()` — необязательный метод только file-сейфа, дописан в контракт `vault/index.js`.
8. SMTP: 587 + STARTTLS и 465 implicit TLS, без шифрования — нельзя.
9. Адрес листа ожидания — за владельцем (ТЗ §22); до ответа ссылка не показывается.
10. Миграция `bitrix24` → `bitrix24-box` автоматическая, с audit `catalog.migrated` и уведомлением владельцу.
Поправки при сведении: у Bitrix24 `keep: time` заменяется скалярами `time.start`, `time.finish`, `time.duration`, `time.processing`, `time.date_start`, `time.date_finish` (проверить живьём), тест `filter-e2e` правится тем же коммитом; условие демо «у владельца есть password_hash» читается как «в `users` есть пользователь с паролем» после миграции контракта команды; порядок шагов прокси — общий, в `docs/ARCHITECTURE.md`.

## Исходные вопросы

1. `readOnly` по умолчанию для новых ключей: включать у CRM/поддержки (Bitrix24, amoCRM, HubSpot, Pipedrive, Zendesk), у остальных выкл./скрыт (предложено), или выключен везде?
2. `mask` для LLM и стрим-провайдеров: не предлагать (предложено) или буферизовать с лимитом 8 MiB?
3. Телефон «голыми цифрами» без `+` не маскируется (иначе ломаются ID и время). Принять пропуск номеров вида `79991234567` или ввести эвристику «11 цифр с 7/8, только в полях с именем phone/tel»?
4. HubSpot: `denyQuery` (`associations`, `propertiesWithHistory`, `archived`) достаточно? Нужен ли тип «Contacts (names only)»? Все поля и формы ответа — только после живой проверки HubSpot/Pipedrive/Zendesk.
5. Демо: один общий демо-владелец для всех посетителей (предложено) или БД на посетителя? Второе дороже, но один посетитель не портит данные другому.
6. MCP на демо: включать в 1.0 или временно закрыть `/mcp` (меньше поверхность)?
7. `vault.names()`: расширить интерфейс сейфа (дописать в ARCHITECTURE.md) или читать `vault.json` напрямую в демо-проверке?
8. E-mail: разрешать порт 465 (implicit TLS) или только 587 + STARTTLS, как в ТЗ §12?
9. Адрес листа ожидания: какой URL и кто его ведёт (форма, Tally, свой Worker)? До ответа README несёт заглушку.
10. Миграция в `bitrix24-box`: автоматически (предложено) или предупреждением в `gateway key list` и подтверждением владельца?
