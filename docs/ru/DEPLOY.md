> English version: [docs/DEPLOY.md](../DEPLOY.md)

# Развёртывание AgentKeyGate

Целевой сервер: Debian 12 или Ubuntu 24.04, Amazon EC2 t3.micro (1 ГБ RAM, swap 1 ГБ создаёт setup.sh).

Два пути: VPS через `scripts/setup.sh` (разделы 1 и 2) и Docker (раздел 7). Демо-экземпляр с третьей линией защиты описан в разделе 10.

Статус проверки (04.11.2026, staging: Ubuntu 24.04, 2 vCPU / 4 ГБ, не AWS, `--vault file`, домен DNS only без проксирования Cloudflare): `setup.sh` с нуля и повторно, сборка нативных модулей от `gateway`, юнит под `SystemCallFilter` (рестарт без SIGSYS, `systemd-analyze security` 1.4 OK), Caddy 2.11 (`caddy validate`, Let's Encrypt), nftables (исходящие только 53/443/465/587), подмена IP заголовками, мастер, вход с 2FA, ключи HubSpot/Pipedrive/Stripe/Twilio, заявка → одобрение → вызов по REST и MCP, фильтр и readOnly на живых ответах, Slack «Send test», `backup.sh` (age) и `gateway restore`, Docker (`docker compose build/up`, healthcheck). Сценарий: `tools/staging-e2e.mjs`. Режим `--behind-cloudflare` с AOP проверен 05.11 (без правила Rate Limiting). Не проверено на живом сервере: сейф `ssm` и IAM-роль на EC2, Telegram, SMTP, демо-экземпляр, `MemoryMax` на файлах Deepgram. Такие места помечены словами «не проверено на живом сервере».

## 1. Что нужно до установки

**Не AWS** (любой VPS с Ubuntu 24.04 или Debian 12): Elastic IP, Security Group и IAM-роль ниже не нужны, ставьте с `--vault file`. Входящие закрывает nftables из `setup.sh` (22, 80, 443); если у провайдера есть свой фаервол, откройте в нём те же порты. С `--vault file` правило nftables для адреса метаданных 169.254.169.254 не ставится: у OpenStack-облаков на этом адресе свои метаданные инстанса. Домен — A-запись на IP сервера без проксирования (DNS only); для пробного запуска без своего домена подойдёт `<ip-через-дефисы>.sslip.io`.

**Elastic IP.** Привяжите его к инстансу, иначе адрес сменится после перезапуска.

**Security Group** (входящие):
- TCP 22: только ваш IP (`/32`);
- TCP 80 и 443: `0.0.0.0/0` (80 нужен для выпуска сертификата Let's Encrypt);
- порт 8080 не открывать (шлюз слушает только 127.0.0.1).

**IAM-роль инстанса.** Создайте роль с доверием `ec2.amazonaws.com`, добавьте политику ниже и прикрепите роль к инстансу. Ключи шлюза лежат в SSM Parameter Store (SecureString) под префиксом `/gateway/`.

Политика (минимальная; условие `aws:SourceVpc` необязательное, см. ниже):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GatewayVault",
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:PutParameter", "ssm:DeleteParameter"],
      "Resource": "arn:aws:ssm:*:*:parameter/gateway/*"
    },
    {
      "Sid": "GatewayKmsViaSsm",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:Encrypt"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "ssm.eu-central-1.amazonaws.com"
        }
      }
    }
  ]
}
```

Важно:
- **Условие `aws:SourceVpc` работает только для запросов через VPC-эндпоинты** (interface endpoints `com.amazonaws.<регион>.ssm` и `...kms`). Если инстанс ходит к публичным адресам SSM (по умолчанию), ключа `aws:SourceVpc` в запросе нет, и все операции с ключами будут запрещены. Тогда либо создайте эндпоинты SSM и KMS в этой VPC, либо удалите оба блока `Condition` из политики.
- Ресурс KMS указан как `*`, потому что `alias/aws/ssm` нельзя указать как ресурс в IAM. Ограничение идёт через `kms:ViaService`. Если параметры зашифрованы своим ключом KMS, укажите его ARN и уберите `kms:ViaService`.
- Регион в `kms:ViaService` замените на ваш (`--region`).

**Как узнать VPC ID.** В консоли: EC2, Instances, выбрать инстанс, вкладка Networking, поле VPC ID. Или с самого сервера (IMDSv2):

```bash
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
MAC=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/mac)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/vpc-id"; echo
```

**DNS в Cloudflare.** Создайте A-запись `gw.example.com` на Elastic IP и выключите проксирование (серая тучка, DNS only). Иначе Let's Encrypt не выдаст сертификат по HTTP-01, а шлюз получит запросы не с реального IP.

## 2. Установка

На сервере от root:

```bash
curl -fsSL https://raw.githubusercontent.com/maximskorohod/agentkeygate/main/scripts/setup.sh -o /root/setup.sh
sudo bash /root/setup.sh --domain gw.example.com --vault ssm --region eu-central-1
```

Что делает скрипт, по шагам:
1. ставит системные пакеты, создаёт swap 1 ГБ, ставит Node.js 22 (NodeSource) и Caddy;
2. создаёт системного пользователя `gateway` без shell;
3. клонирует репозиторий в `/opt/agentkeygate/app` (код принадлежит root, `gateway` писать в него не может), собирает зависимости от непривилегированного пользователя (`npm ci --ignore-scripts`, затем `npm rebuild argon2 better-sqlite3`);
4. создаёт `/var/lib/agentkeygate` (данные) и `/etc/agentkeygate/env` (переменные `GW_*`, права 0600);
5. ставит systemd-юнит `gateway.service` с харденингом, конфиг Caddy с вашим доменом, правила nftables и cron-задачу бэкапа;
6. запускает сервисы, ждёт `/healthz` и вызывает `gateway init`.

Проверено на staging 04.11: сборка нативных модулей от `gateway`, запуск и рестарт юнита под `SystemCallFilter` без `Bad system call`, `caddy validate` на Caddy 2.11. Не проверено на живом сервере: хватает ли `MemoryMax=512M` при больших файлах Deepgram. Команды для проверки: `systemd-analyze security gateway`, `journalctl -u gateway -n 50`, `caddy validate --config /etc/caddy/Caddyfile`.

В конце скрипт печатает одноразовую ссылку мастера:

```
==> Setup wizard: gateway init
...ссылка вида https://gw.example.com/setup/<код>...
```

Ссылка действительна 15 минут и открывается один раз. Откройте её в браузере и пройдите мастер: пароль (не короче 12 символов), 2FA (обязательно, сохраните резервные коды), Telegram (необязательно).

Повторный запуск `setup.sh` безопасен: он обновляет код и конфиги и перезапускает сервисы. Если ссылка истекла до конца мастера, просто запустите его ещё раз. После пройденного мастера `setup.sh` не вызывает `gateway init` (он сбросил бы пароль и 2FA); открыть мастер заново можно флагом `--init` или по разделу 4.

**Домен через Cloudflare с проксированием** (оранжевая тучка): режим SSL/TLS **Full (strict)** и флаг `--behind-cloudflare`. Caddy берёт IP клиента из `CF-Connecting-IP` только от адресов Cloudflare, nftables пускает 80/443 только с них; в Security Group откройте 80/443 тоже только для диапазонов www.cloudflare.com/ips. Cloudflare в этом режиме видит трафик, включая ключи.

**Authenticated Origin Pulls (AOP).** В режиме `--behind-cloudflare` Caddy требует клиентский сертификат Cloudflare, поэтому прямое подключение к IP сервера не проходит TLS-рукопожатие. Включение:

1. В панели Cloudflare: SSL/TLS → Origin Server → вкладка Authenticated Origin Pulls → раздел **Global** → On. Global AOP использует общий сертификат Cloudflare и действует на все проксируемые записи зоны; источникам, которые не просят клиентский сертификат, он не мешает. Сертификат один на всех клиентов Cloudflare: он подтверждает, что запрос пришёл через сеть Cloudflare, а не через вашу зону. Если нужна привязка к своей зоне, настройте zone-level AOP со своим сертификатом.
2. Скачайте CA global AOP (`https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem`, ссылка со страницы Authenticated Origin Pulls → Global) и положите на сервер как `/etc/caddy/cloudflare-origin-pull-ca.pem`. Скрипт сам файл не скачивает.
3. Сверьте `sha256sum /etc/caddy/cloudflare-origin-pull-ca.pem` с константой `CF_CA_SHA256` в начале `setup.sh` (`c14fed0c…b843`, CA до 01.11.2029; сверено 04.11.2026 двумя загрузками с разных машин).
4. Запустите `setup.sh --behind-cloudflare ...`. Скрипт откажется работать, если отпечаток не совпал. Если Cloudflare выпустил новый CA, передайте его отпечаток флагом `--cf-ca-sha256 <отпечаток>` после такой же сверки.

**Без Cloudflare** (DNS only, по умолчанию) подмена IP проверяется так: запрос с поддельными `X-Forwarded-For`, `X-Real-IP` и `CF-Connecting-IP` на неверный пароль, затем в журнале входа (`sqlite3 -readonly /var/lib/agentkeygate/gw.db "SELECT target FROM audit WHERE action='login.fail' ORDER BY rowid DESC LIMIT 1"`) должен стоять настоящий адрес клиента. Caddy без `trusted_proxies` подменяет заголовок своим адресом клиента, шлюз доверяет только loopback. Проверено на staging 04.11; там же HTTPS на голый IP сервера не отвечает (сертификат выдан только на домен).

Порядок важен: сначала Global AOP в панели и прокси у записи, потом `setup.sh --behind-cloudflare`. Если Global AOP выключен, Caddy обрывает соединение после рукопожатия, и Cloudflare показывает ошибку **520** (проверено на staging 05.11). После переключения сверьте состояние тумблера перезагрузкой страницы.

**Rate Limiting на `/login`.** На тарифе Free в правиле доступно только поле Path, поля Host нет. Если в зоне есть другие проксируемые сервисы с путём `/login`, правило подействует и на них. Период и блокировка на Free фиксированные: 10 с, счётчик по IP.

Три проверки вручную для режима `--behind-cloudflare`, что подмена IP не проходит (`<your-host>` замените на свой домен, `<server-ip>` на IP сервера). Проверено на staging 05.11: прямое подключение не отвечает, через Cloudflare 200, поддельный `X-Forwarded-For` в журналах не появляется, поддельный `CF-Connecting-IP` Cloudflare отклоняет сам (403), в `login.fail` стоит настоящий адрес клиента. Продление сертификата Let's Encrypt за прокси не проверено:

```bash
# 1. Прямое подключение в обход Cloudflare не должно пройти (ошибка рукопожатия или таймаут nftables):
curl -sk --resolve <your-host>:443:<server-ip> https://<your-host>/healthz -o /dev/null -w '%{http_code}\n'

# 2. Подделка заголовков с прямого подключения тоже не должна дойти до шлюза и не должна менять IP в журнале входа:
curl -sk --resolve <your-host>:443:<server-ip> https://<your-host>/healthz \
  -H 'X-Forwarded-For: 203.0.113.7' -H 'CF-Connecting-IP: 203.0.113.7' -o /dev/null -w '%{http_code}\n'

# 3. Через Cloudflare запрос проходит, а подделанный X-Forwarded-For в журнале не появляется:
curl -s https://<your-host>/healthz -H 'X-Forwarded-For: 203.0.113.7'
sudo journalctl -u gateway -n 20 --no-pager | grep 203.0.113.7 || echo "поддельный адрес в журнале не найден"
```

Ожидаемо: пункты 1 и 2 завершаются ошибкой соединения (код 000) или отказом, пункт 3 отвечает, поддельного адреса в журнале нет. Если пункты 1 и 2 вернули 200, AOP не работает: проверьте, что строки `#cf` в `/etc/caddy/Caddyfile` раскомментированы (`grep client_auth /etc/caddy/Caddyfile`).

**Закрытый репозиторий**: заведите на сервере голый репозиторий (`git init --bare /srv/agentkeygate.git`), залейте ветку `git push <ssh-хост>:/srv/agentkeygate.git main` и передайте `--repo /srv/agentkeygate.git`. Токен GitHub на сервере не нужен. Сам `setup.sh` можно достать из того же репозитория: `git --git-dir=/srv/agentkeygate.git show main:scripts/setup.sh > /root/setup.sh` (проверено на staging). Если клонируете голый репозиторий руками, указывайте ветку (`git clone --branch main …`): `HEAD` у нового голого репозитория указывает на несуществующую ветку, и клон получается пустым.

## 3. Обновление

Запустите `setup.sh` ещё раз с теми же аргументами: он обновит код, соберёт зависимости от непривилегированного пользователя (`npm ci --ignore-scripts`, затем `npm rebuild argon2 better-sqlite3`) и перезапустит сервисы. Не запускайте `npm ci` от root вручную: скрипты установки пакетов выполнились бы с правами root.

## 4. Повторно открыть мастер (`gateway init`)

`init` сбрасывает пароль, 2FA, сессии и пропуска. Ключи и агенты остаются. Команда (от root, переменные берутся из `/etc/agentkeygate/env`):

```bash
sudo bash -c 'set -a; . /etc/agentkeygate/env; set +a; runuser -u gateway -- env -C /opt/agentkeygate/app -i PATH=/usr/bin:/bin $(env | grep "^GW_") /usr/bin/node bin/gateway.js init'
```

## 5. Резервные копии и восстановление

Бэкап делается каждую ночь в 03:17 (`/etc/cron.d/agentkeygate`, скрипт `scripts/backup.sh`). Копии лежат в `/var/backups/agentkeygate/`, старше 30 дней удаляются.

Шифрование:
- **age** (предпочтительно): `sudo apt install age`, положите публичный ключ получателя в `/etc/agentkeygate/backup.age.pub`. Приватный ключ храните вне сервера.
- **gpg** (если age нет): положите пароль в `/etc/agentkeygate/backup.pass` (0600, root). Пароль хранится на том же сервере, поэтому копия защищает только от утечки самих файлов бэкапа.
- Шифрование обязательно. Если нет ни age с ключом, ни gpg с паролем, скрипт пишет ошибку, выходит с кодом 1 и ничего не сохраняет (открытых копий на диске не бывает).
- Файловый сейф (`GW_VAULT=file`): в копию входят `vault.json` и `master.key`, файл называется `gw-ДАТА.tar.age|gpg` (внутри `gw.db`, `vault.json`, `master.key`). Мастер-ключ лежит в том же шифруемом архиве, поэтому его защищает только шифрование: храните приватный ключ age вне сервера. Для сейфа ssm в копии только база.
- Ротация аудита (старше 90 дней, архивом, шлюз остановлен): `gateway audit rotate --days 90 --out /var/backups/agentkeygate/audit`. Запись в журнале только на добавление, поэтому плановой очистки через DELETE нет.

Выгрузка в S3 (необязательно): в `/etc/agentkeygate/backup.env` задайте `S3_BUCKET=...` и при желании `S3_PREFIX=...`. Нужен `aws` CLI и IAM-право `s3:PutObject` для роли инстанса. Срок хранения в S3 задаётся lifecycle-правилом бакета (30 дней).

Восстановление:

```bash
# 1. Расшифровать копию (на вашей машине или на сервере):
age -d -i ~/backup.key -o gw.db gw-2026-11-01.db.age
#    или для gpg:
gpg --batch --pinentry-mode loopback --passphrase-file /etc/agentkeygate/backup.pass -d -o gw.db gw-2026-11-01.db.gpg

#    для файлового сейфа архив gw-ДАТА.tar.age|gpg: расшифровать так же, затем распаковать:
#    tar -xf gw.tar  # gw.db, vault.json, master.key
# 2. Остановить шлюз. Для файлового сейфа сначала вернуть сейф в каталог данных:
sudo systemctl stop gateway
#    sudo install -o gateway -g gateway -m 0600 vault.json master.key /var/lib/agentkeygate/   (по файлу, не пачкой, если имена разные)
#    и положить gw.db туда, где его может прочитать gateway:
sudo install -o gateway -g gateway -m 0600 gw.db /var/lib/agentkeygate/restore.db
rm -f gw.db

# 3. Восстановить (ротируется ключ подписи пропусков, все пропуска отзываются, сессии, одноразовые ссылки, ожидающие заявки
#    и временные секреты 2FA сбрасываются):
sudo bash -c 'set -a; . /etc/agentkeygate/env; set +a; runuser -u gateway -- env -C /opt/agentkeygate/app -i PATH=/usr/bin:/bin $(env | grep "^GW_") /usr/bin/node bin/gateway.js restore /var/lib/agentkeygate/restore.db'

# 4. Запустить и удалить временный файл:
sudo rm -f /var/lib/agentkeygate/restore.db
sudo systemctl start gateway
```

После восстановления войдите заново. Если пароль или 2FA не подходят, повторите мастер (раздел 4).

Проверено на staging 04.11 (age, файловый сейф): архив `gw-ДАТА.tar.age` без открытых копий рядом, restore по шагам выше отозвал все пропуска и сессии, ключи и агенты остались, после повторного одобрения вызовы в сервисы проходят (сейф расшифровывается восстановленным `master.key`). Ключ age для пробы создавался командой `age-keygen` на сервере; в рабочей установке создавайте его на своей машине и кладите на сервер только публичную часть.

## 6. Проверка и логи

```bash
systemctl status gateway caddy nftables chrony
curl -s https://gw.example.com/healthz          # публичная проверка через Caddy
journalctl -u gateway -f                        # логи шлюза
journalctl -u caddy -f                          # логи Caddy (ошибки TLS и прокси)
tail -f /var/log/caddy/access.log               # доступ без query string и заголовков
sudo nft list ruleset | less                    # текущий фаервол
sudo tail -n 50 /var/log/agentkeygate-backup.log
```

Логи блокировок фаервола (`agw-ssrf-…`, `agw-out-drop`, `agw-in-drop`) пишутся в журнал ядра: `journalctl -k | grep agw-`.

## 7. Docker

Файлы: `Dockerfile`, `docker-compose.yml`, `Caddyfile.docker`, `.env.example`. Запускаются два контейнера: шлюз (без публикации порта, файловая система только для чтения, без capabilities, не root) и Caddy (порты 80 и 443, сертификат Let's Encrypt).

```bash
cp .env.example .env        # заполните DOMAIN и GW_PUBLIC_URL (https://gw.example.com)
docker compose up -d
docker compose exec gateway node bin/gateway.js init   # печатает одноразовую ссылку мастера (15 минут)
```

Что учесть:
- В Docker сейф только файловый (`GW_VAULT=file`), данные лежат в томе `gateway-data` (`/data`). Мастер-ключ лежит рядом с сейфом, поэтому доступ к тому равен доступу ко всем ключам.
- Caddy стоит в другом контейнере, и шлюз по умолчанию доверяет заголовку `X-Forwarded-For` только с loopback. Чтобы блокировки, лимиты и журнал входа видели адрес клиента, а не адрес контейнера, `docker-compose.yml` уже задаёт `GW_TRUST_PROXY=172.16.0.0/12` (подсети Docker). Если ваша сеть compose вне этого диапазона, переопределите значение. Не расширяйте его до сетей, где есть чужие хосты.
- Бэкап для Docker `scripts/backup.sh` не делает (он рассчитан на VPS). Копируйте том `gateway-data` сами и шифруйте копию (age или gpg); восстановление: `docker compose exec gateway node bin/gateway.js restore <файл>` после остановки записи.
- nftables и systemd-харденинг из раздела 2 в Docker не применяются.
- Не ставьте Docker на сервер, где `setup.sh` уже установил `deploy/nftables.conf`: файл начинается с `flush ruleset`, и каждый `systemctl restart nftables` (в том числе повторный `setup.sh`) стирает правила Docker. Контейнеры после этого остаются без исходящей сети (сборка падает на `apk add`, шлюз не достучится до сервисов), пока не выполнить `systemctl restart docker`. Проверено на staging 04.11.

Проверено на staging 04.11 (Docker 29, Compose 2.40): `docker compose build` и `up`, healthcheck `healthy`, `/healthz`, процесс от `gateway` (не root), файловая система `/app` только для чтения, `/data` доступен на запись, `gateway init` в контейнере печатает ссылку мастера, `caddy validate` для `Caddyfile.docker`. Контейнер Caddy с выпуском сертификата не запускался (порты 80/443 на том сервере заняты systemd-вариантом).

## 8. Переменные окружения

На VPS их пишет `setup.sh` в `/etc/agentkeygate/env`, в Docker они берутся из `.env`.

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `GW_PUBLIC_URL` | `http://127.0.0.1:8080` | Внешний адрес, который попадает в ссылки и уведомления |
| `GW_HOST`, `GW_PORT` | `127.0.0.1`, `8080` | Где слушает шлюз (наружу не открывать, ходит Caddy) |
| `GW_DATA_DIR` | `./data` | Каталог базы `gw.db`, `vault.json`, `master.key` |
| `GW_VAULT` | `file` | `file` или `ssm` |
| `GW_VAULT_PREFIX`, `GW_SSM_REGION` | `/gateway`, `eu-central-1` | Только для `ssm` |
| `GW_TRUST_PROXY` | `loopback` | Адреса или подсети прокси, чей `X-Forwarded-For` принимается |
| `GW_LANG` | `en` | Язык интерфейса: `en` или `ru` |
| `GW_TZ` | `UTC` | Часовой пояс шлюза |
| `GW_LOG_LEVEL` | `info` | Уровень журнала |
| `GW_PROXY_RATE_PER_MIN` | `300` | Лимит вызовов через прокси на агента в минуту |
| `GW_MCP_ENABLED` | включено | `0`, `false` или `off` выключают MCP на `/mcp` |
| `GW_MCP_ORIGINS` | пусто | Разрешённые Origin для браузерных MCP-клиентов, через запятую |
| `GW_MCP_MAX_SESSIONS`, `GW_MCP_MAX_SESSIONS_PER_AGENT`, `GW_MCP_IDLE_SEC`, `GW_MCP_MAX_LIFETIME_SEC` | `200`, `5`, `900`, `86400` | Лимиты MCP-сессий |
| `GW_MCP_MAX_RESPONSE`, `GW_MCP_BODY_LIMIT`, `GW_MCP_CALL_PARALLEL` | `65536`, `262144`, `4` | Байт ответа сервиса для модели, размер тела MCP-запроса, одновременных `call` на сессию |
| `GW_AUTH_PROVIDER` | локальный | Модуль входа |
| `GW_WAITLIST_URL` | пусто | Ссылка «Cloud: join the waitlist» (только https) |
| `GW_DEMO`, `GW_DEMO_RESET_SEC`, `GW_PROD_HOSTS` | выкл, `3600`, пусто | Демо-режим, см. раздел 10 |

## 9. Caddy

Конфиг VPS: `deploy/Caddyfile` (setup.sh подставляет домен и ставит в `/etc/caddy/Caddyfile`). Для Docker: `Caddyfile.docker`. Что делают оба: TLS от Let's Encrypt, заголовки безопасности (HSTS, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`: при `no-referrer` браузер отправляет формы с `Origin: null`, и CSRF-проверка их отклоняет), лимит тела 210 МБ (для Deepgram; остальные запросы ограничивает само приложение до 2 МБ), журнал доступа без query string и без заголовков запроса, проксирование на шлюз без буферизации и с таймаутом заголовков ответа 620 с.

Особенности VPS-варианта: журнал дополнительно маскирует IP до /16 (IPv4) и /32 (IPv6); строки с меткой `#cf` включаются только флагом `--behind-cloudflare` (доверие `CF-Connecting-IP` только от адресов Cloudflare и Authenticated Origin Pulls). Синтаксис фильтров журнала и `trust_pool` проверен на Caddy 2.11; на другой версии проверьте `caddy validate`.

## 10. Demo instance

Демо-режим (`GW_DEMO=1`) нужен для публичного экземпляра-витрины: в нём нет реальных ключей и нет исходящих соединений, данные сбрасываются раз в час. Защита в три линии:

1. **Запуск.** Шлюз отказывается стартовать (код выхода 1, до открытия порта), если нашёл реальные данные: сейф не `file`, заданы `AWS_*`, `GW_SSM_*` или `GW_VAULT_PREFIX`, `GW_DATA_DIR` не задан явно, каталог данных не пуст и без маркера демо, в сейфе или базе есть чужие ключи, у владельца есть пароль, `GW_PUBLIC_URL` совпадает с хостом из `GW_PROD_HOSTS`.
2. **Процесс.** Сетевой guard внутри Node блокирует исходящие TCP-соединения и DNS, вызовы идут во встроенный мок. Guard не перехватывает UDP (`dgram`) и дочерние процессы.
3. **Сервер.** Ограничение на уровне ОС, которое работает даже при ошибке в коде: systemd и nftables, как ниже.

Переменные демо (в `/etc/agentkeygate/env` отдельного экземпляра):

```
GW_DEMO=1
GW_DATA_DIR=/var/lib/agentkeygate-demo
GW_VAULT=file
GW_PUBLIC_URL=https://demo.example.com
GW_PROD_HOSTS=gw.example.com
```

- `GW_DATA_DIR` задаётся явно и каталог должен быть пустым при первом запуске (шлюз сам создаст маркер `.demo-data`). Каталог, где уже проходил мастер `gateway init`, не подойдёт.
- `GW_VAULT=file`, и ни одной переменной `AWS_*`, `GW_SSM_*`, `GW_VAULT_PREFIX`. Файл env, созданный `setup.sh`, содержит `GW_VAULT_PREFIX` и `GW_SSM_REGION`: для демо удалите эти строки.
- `GW_PROD_HOSTS` перечисляет хосты боевого шлюза, через запятую. Это страховка от запуска демо с боевым адресом.
- Демо ставится на отдельную машину или отдельный каталог и пользователя; не на сервер с боевым шлюзом.

**Линия 3a: systemd.** Drop-in для юнита демо (`systemctl edit gateway`):

```ini
[Service]
IPAddressDeny=any
IPAddressAllow=localhost
```

`IPAddressDeny=any` запрещает юниту любой IP-трафик, `IPAddressAllow=localhost` оставляет loopback, через который Caddy ходит к шлюзу на 127.0.0.1:8080. Проверка: `systemctl show gateway -p IPAddressDeny -p IPAddressAllow`.

**Линия 3b: nftables.** Отдельная таблица с приоритетом раньше правил из `deploy/nftables.conf`: исходящее от пользователя `gateway` разрешено только через loopback и как ответы на установленные входящие соединения, остальное отбрасывается.

```
table inet agw_demo {
  chain output {
    type filter hook output priority filter - 10; policy accept;

    meta skuid gateway oif "lo" accept
    meta skuid gateway ct state established,related accept
    meta skuid gateway limit rate 6/minute log prefix "agw-demo-out: "
    meta skuid gateway drop
  }
}
```

Загрузка: сохраните как `/etc/nftables-demo.conf`, проверьте `nft -c -f /etc/nftables-demo.conf`, примените `nft -f /etc/nftables-demo.conf`. Чтобы правила переживали перезагрузку, подключите файл строкой `include "/etc/nftables-demo.conf"` в `/etc/nftables.conf`. Учтите, что `deploy/nftables.conf` начинается с `flush ruleset` и повторный запуск `setup.sh` перезапишет конфиг: после него верните строку `include`.

Проверка из-под пользователя: `sudo -u gateway curl -m 5 -sS https://example.com` должна завершиться ошибкой, а `curl -s https://demo.example.com/healthz` снаружи отвечать.

Проверено на VPS отдельным юнитом на loopback: шлюз запускается и перезапускается в демо-режиме, процесс с `IPAddressDeny=any` и `IPAddressAllow=localhost` наружу не выходит. Не проверено на живом сервере: правила nftables, демо по публичному адресу за Caddy, юнит с `SystemCallFilter` и `IPAddressDeny` вместе.
