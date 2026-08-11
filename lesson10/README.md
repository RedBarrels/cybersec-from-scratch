# bash_security_lab — заняття №10

Скрипти до заняття «Bash для кібербезпеки: логи, мережа, аудит»
курсу **Кібербезпека з нуля**.

Усі скрипти:
- проходять `shellcheck` без зауважень;
- не потребують sudo для базової роботи;
- нічого не змінюють у системі (read-only);
- визначають платформу самі (Linux / macOS / WSL);
- мають детальні коментарі українською — код призначений для читання, а не лише для запуску.

## Швидкий старт

```bash
chmod +x *.sh
./make_samples.sh                       # згенерувати тестові логи в ./samples
./analyze_auth.sh samples/auth.log 5
./analyze_access.sh samples/access.log
./sec_audit.sh
./port_scan.sh localhost
./scan_network.sh 192.168.1             # ТІЛЬКИ власна мережа
```

## Скрипти

| Файл | Що робить |
|---|---|
| `make_samples.sh` | генерує синтетичні `auth.log` і `access.log` з атаками |
| `analyze_auth.sh` | брутфорс SSH: топ IP, перебрані імена, успішні входи, перетин «брутфорсив і зайшов» |
| `analyze_access.sh` | логи веб-сервера: коди відповіді, SQLi, path traversal, XSS, сканери |
| `scan_network.sh` | пошук живих хостів у /24 (ICMP + запасний TCP-метод), паралельно |
| `port_scan.sh` | TCP connect-скан портів засобами `/dev/tcp` |
| `sec_audit.sh` | аудит хоста: 15 перевірок, PASS/FAIL/WARN/SKIP, код повернення для CI |

## Сумісність

| Скрипт | Linux | macOS | WSL | Git Bash |
|---|---|---|---|---|
| `make_samples.sh` | ✅ | ✅ | ✅ | ✅ |
| `analyze_auth.sh` | ✅ | ✅ | ✅ | ✅ |
| `analyze_access.sh` | ✅ | ✅ | ✅ | ✅ |
| `scan_network.sh` | ✅ | ✅ | ⚠️ бачить мережу WSL, не Windows | ❌ |
| `port_scan.sh` | ✅ | ⚠️ потрібен `gtimeout` або `nc` | ✅ | ❌ |
| `sec_audit.sh` | ✅ | ✅ | ⚠️ частина перевірок SKIP | ❌ |

Git Bash не підтримує `/dev/tcp`. Під Windows працюйте у WSL.

macOS постачається з bash 3.2 — поставте свіжий:
```bash
brew install bash coreutils
```

## Законність

`scan_network.sh` і `port_scan.sh` запускайте **лише** проти систем, якими володієте
або на які маєте письмовий дозвіл. Для практики: власна мережа, лабораторна VM,
`scanme.nmap.org`, HackTheBox, TryHackMe.

## Перевірка перед комітом

```bash
shellcheck *.sh
```
