#!/usr/bin/env bash
#
# make_samples.sh — генератор тестових логів
# Курс «Кібербезпека з нуля», заняття №10
#
# Навіщо: щоб перевірити скрипти аналізу, потрібні логи з атаками.
# Брати реальний /var/log/auth.log з робочого сервера — погана ідея
# (там є реальні IP, імена користувачів, інколи токени в URL).
# Тому генеруємо синтетичні логи такого самого формату.
#
# Запуск:  ./make_samples.sh [каталог]
# За замовчуванням складає файли в ./samples/

set -euo pipefail

OUT_DIR="${1:-samples}"          # ${1:-...} — перший аргумент або значення за замовчуванням
mkdir -p "$OUT_DIR"

AUTH="$OUT_DIR/auth.log"
ACCESS="$OUT_DIR/access.log"

# ---------------------------------------------------------------------------
# 1. auth.log — журнал автентифікації (формат sshd на Debian/Ubuntu)
# ---------------------------------------------------------------------------
# Реальний рядок виглядає так:
#   Aug  9 03:14:07 web01 sshd[2211]: Failed password for invalid user admin \
#       from 203.0.113.7 port 51314 ssh2
# Нам важливі три речі: дія (Failed/Accepted), користувач, IP.

: > "$AUTH"                       # : > file — очистити або створити порожній файл

# Атакувальник №1: класичний брутфорс словником імен
for user in root admin test oracle postgres ubuntu git jenkins backup deploy; do
    for i in 1 2 3 4 5; do
        printf 'Aug  9 03:%02d:%02d web01 sshd[%d]: Failed password for invalid user %s from 203.0.113.7 port %d ssh2\n' \
            $((RANDOM % 60)) $((RANDOM % 60)) $((2000 + RANDOM % 500)) "$user" $((40000 + RANDOM % 20000)) >> "$AUTH"
    done
done

# Атакувальник №2: цілиться в один існуючий обліковий запис
for i in $(seq 1 18); do
    printf 'Aug  9 04:%02d:%02d web01 sshd[%d]: Failed password for deploy from 198.51.100.42 port %d ssh2\n' \
        $((RANDOM % 60)) $((RANDOM % 60)) $((2500 + RANDOM % 500)) $((40000 + RANDOM % 20000)) >> "$AUTH"
done

# Атакувальник №3: кілька спроб — схоже на людину, що забула пароль
for i in 1 2 3; do
    printf 'Aug  9 05:1%d:0%d web01 sshd[3100]: Failed password for artem from 192.0.2.15 port 5222%d ssh2\n' \
        "$i" "$i" "$i" >> "$AUTH"
done

# Успішні входи — те, що має цікавити найбільше після брутфорсу
{
    printf 'Aug  9 05:20:11 web01 sshd[3155]: Accepted publickey for artem from 192.0.2.15 port 52231 ssh2: RSA SHA256:abc\n'
    printf 'Aug  9 06:02:44 web01 sshd[3402]: Accepted password for deploy from 198.51.100.42 port 41007 ssh2\n'
    printf 'Aug  9 06:03:01 web01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash\n'
    printf 'Aug  9 06:05:12 web01 sshd[3510]: Invalid user oracle from 203.0.113.7 port 51999\n'
} >> "$AUTH"

# ---------------------------------------------------------------------------
# 2. access.log — журнал веб-сервера (nginx/apache combined)
# ---------------------------------------------------------------------------
# Формат combined:
#   IP - - [дата] "МЕТОД URL HTTP/1.1" код розмір "referer" "user-agent"
# Поля розділені пробілами, тому awk бачить: $1 = IP, $7 = URL, $9 = код.

: > "$ACCESS"

ua_normal='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/138.0 Safari/537.36'
ua_bot='sqlmap/1.9.2#stable (https://sqlmap.org)'
ua_scan='Mozilla/5.0 (compatible; Nuclei - Open-source project)'

# Нормальний трафік
for i in $(seq 1 40); do
    printf '198.51.100.%d - - [09/Aug/2026:10:%02d:%02d +0300] "GET /index.html HTTP/1.1" 200 4521 "-" "%s"\n' \
        $((10 + RANDOM % 40)) $((RANDOM % 60)) $((RANDOM % 60)) "$ua_normal" >> "$ACCESS"
done

# Сканер, що шукає забуті файли (найчастіша реальна атака на веб)
for path in /.env /.git/config /wp-admin/ /admin /phpmyadmin/ /backup.zip /config.php.bak /.aws/credentials; do
    printf '203.0.113.66 - - [09/Aug/2026:11:%02d:%02d +0300] "GET %s HTTP/1.1" 404 162 "-" "%s"\n' \
        $((RANDOM % 60)) $((RANDOM % 60)) "$path" "$ua_scan" >> "$ACCESS"
done

# SQL-ін'єкція
{
    printf '203.0.113.66 - - [09/Aug/2026:11:31:02 +0300] "GET /search?q=1%%27+UNION+SELECT+null,version()--+- HTTP/1.1" 500 512 "-" "%s"\n' "$ua_bot"
    printf '203.0.113.66 - - [09/Aug/2026:11:31:09 +0300] "GET /search?q=1+OR+1=1 HTTP/1.1" 200 4211 "-" "%s"\n' "$ua_bot"
} >> "$ACCESS"

# Path traversal і XSS
{
    printf '192.0.2.200 - - [09/Aug/2026:12:04:41 +0300] "GET /files?name=../../../../etc/passwd HTTP/1.1" 403 199 "-" "curl/8.9.1"\n'
    printf '192.0.2.200 - - [09/Aug/2026:12:05:03 +0300] "GET /comment?text=<script>alert(1)</script> HTTP/1.1" 200 881 "-" "curl/8.9.1"\n'
} >> "$ACCESS"

# Брутфорс форми входу: багато 401 з однієї адреси
for i in $(seq 1 25); do
    printf '198.51.100.42 - - [09/Aug/2026:13:%02d:%02d +0300] "POST /login HTTP/1.1" 401 231 "-" "python-requests/2.32"\n' \
        $((RANDOM % 60)) $((RANDOM % 60)) >> "$ACCESS"
done

echo "Готово:"
echo "  $AUTH     ($(wc -l < "$AUTH") рядків)"
echo "  $ACCESS   ($(wc -l < "$ACCESS") рядків)"
