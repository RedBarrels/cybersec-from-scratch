#!/usr/bin/env bash
#
# analyze_access.sh — пошук атак у логах веб-сервера
# Курс «Кібербезпека з нуля», заняття №10
#
# Формат combined (nginx і apache пишуть однаково):
#   198.51.100.18 - - [09/Aug/2026:10:23:34 +0300] "GET /index.html HTTP/1.1" 200 4521 "-" "Mozilla/5.0 ..."
#    $1           $2 $3 $4          $5      $6      $7  $8            $9  $10
#
# Для awk важливо запам'ятати три поля:
#   $1  — IP клієнта
#   $7  — запитаний URL
#   $9  — код відповіді HTTP
#
# Запуск:
#   ./analyze_access.sh samples/access.log
#   ./analyze_access.sh /var/log/nginx/access.log 20
#
# Скрипт лише читає файл і нічого не змінює.

set -euo pipefail

LOG_FILE="${1:?Вкажіть файл: $0 samples/access.log}"
#  ${1:?текст} — якщо аргумента немає, bash сам виведе текст і завершить скрипт.
#  Коротший і надійніший спосіб, ніж писати перевірку вручну.

TOP_N="${2:-10}"

[[ -r "$LOG_FILE" ]] || { echo "Не можу прочитати: $LOG_FILE" >&2; exit 1; }

if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
    RED=$(tput setaf 1); YELLOW=$(tput setaf 3); GREEN=$(tput setaf 2)
    BOLD=$(tput bold);   RESET=$(tput sgr0)
else
    RED=""; YELLOW=""; GREEN=""; BOLD=""; RESET=""
fi

total=$(wc -l < "$LOG_FILE" | tr -d ' ')

printf '%s\n' "${BOLD}=== Аналіз логів веб-сервера ===${RESET}"
printf 'Файл    : %s\n' "$LOG_FILE"
printf 'Запитів : %s\n\n' "$total"

# --- 1. Топ клієнтів ---------------------------------------------------------
printf '%s--- Топ-%s IP за кількістю запитів ---%s\n' "$BOLD" "$TOP_N" "$RESET"
awk '{print $1}' "$LOG_FILE" \
    | sort | uniq -c | sort -rn | head -n "$TOP_N" \
    | awk '{printf "  %6d  %s\n", $1, $2}'
echo

# --- 2. Розподіл кодів відповіді --------------------------------------------
#
# Це найшвидший спосіб побачити ненормальний трафік:
#   багато 404  → хтось перебирає шляхи (сканер)
#   багато 401  → брутфорс форми входу
#   багато 500  → або зламали, або самі щось зламали
printf '%s--- Коди відповіді ---%s\n' "$BOLD" "$RESET"
awk '{print $9}' "$LOG_FILE" \
    | sort | uniq -c | sort -rn \
    | while read -r count code; do
        case "$code" in
            2*) mark="${GREEN}ok${RESET}" ;;
            3*) mark="редірект" ;;
            4[0-9][0-9]) mark="${YELLOW}помилка клієнта${RESET}" ;;
            5*) mark="${RED}помилка сервера${RESET}" ;;
            *)  mark="" ;;
        esac
        printf '  %6d  %-5s %b\n' "$count" "$code" "$mark"
        #  %b у printf — вивести рядок, розкриваючи escape-послідовності.
        #  Потрібне тут, бо в $mark лежать кольорові коди.
      done
echo

# --- 3. Пошук ознак атак -----------------------------------------------------
#
# Це не «виявлення вторгнень», а перший грубий фільтр. Він дає багато
# хибних спрацювань (у нормальному URL теж може бути слово "admin"),
# але за 5 секунд показує, чи варто дивитися далі.
#
# grep -i   — без урахування регістру (UNION і union)
# grep -c   — порахувати рядки, а не показати їх
# grep -E   — розширені регулярні вирази. Саме -E, а не -P: perl-регулярки
#             є в GNU grep, але їх немає в macOS. Кросплатформенний код — -E.

printf '%s--- Ознаки атак ---%s\n' "$BOLD" "$RESET"

check_pattern() {
    # $1 — людська назва, $2 — регулярний вираз
    local label="$1" pattern="$2" count
    count=$(grep -icE "$pattern" "$LOG_FILE" || true)
    #  || true — grep віддає код 1, коли збігів нема; для нас це не помилка

    if (( count > 0 )); then
        printf '  %s[%3d]%s %s\n' "$RED" "$count" "$RESET" "$label"
    else
        printf '  %s[  0]%s %s\n' "$GREEN" "$RESET" "$label"
    fi
}

check_pattern "SQL-ін'єкція (union select, or 1=1)"  'union[ +]+select|or[ +]+1=1|sleep\(|benchmark\('
check_pattern "Path traversal (../ або %2e%2e)"      '\.\./|%2e%2e'
check_pattern "XSS (<script>, javascript:)"          '<script|%3Cscript|javascript:'
check_pattern "Command injection (;, |, \$( )"       '%3B|%7C|%24%28|;cat|;ls|\|id'
check_pattern "Пошук секретів (.env, .git, backup)"  '/\.env|/\.git|/\.aws|backup|\.bak|\.sql'
check_pattern "Панелі керування (wp-admin, phpmyadmin)" 'wp-admin|wp-login|phpmyadmin|/admin'
check_pattern "Відомі сканери в User-Agent"          'sqlmap|nikto|nuclei|masscan|acunetix|dirbuster|zgrab'
echo

# --- 4. Хто отримує найбільше 404 -------------------------------------------
#
# Один клієнт із десятками 404 — це майже завжди сканер каталогів.
printf '%s--- Топ-%s IP за кількістю 404 (перебір шляхів) ---%s\n' "$BOLD" "$TOP_N" "$RESET"
awk '$9 == 404 {print $1}' "$LOG_FILE" \
    | sort | uniq -c | sort -rn | head -n "$TOP_N" \
    | awk '{printf "  %6d  %s\n", $1, $2}'
echo
#  awk '$9 == 404 {...}' — умова перед блоком: виконати блок лише для рядків,
#  де дев'яте поле дорівнює 404. Це замінює зв'язку grep | awk.

# --- 5. Хто отримує найбільше 401/403 ---------------------------------------
printf '%s--- Топ-%s IP за 401/403 (брутфорс або заборонений доступ) ---%s\n' "$BOLD" "$TOP_N" "$RESET"
result=$(awk '$9 == 401 || $9 == 403 {print $1}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -n "$TOP_N")
if [[ -z "$result" ]]; then
    printf '  немає\n'
else
    printf '%s\n' "$result" | awk '{printf "  %6d  %s\n", $1, $2}'
fi
echo

# --- 6. Найпопулярніші URL ---------------------------------------------------
printf '%s--- Топ-%s запитаних URL ---%s\n' "$BOLD" "$TOP_N" "$RESET"
awk '{print $7}' "$LOG_FILE" \
    | cut -c1-60 \
    | sort | uniq -c | sort -rn | head -n "$TOP_N" \
    | awk '{printf "  %6d  %s\n", $1, $2}'
echo
#  cut -c1-60 — обрізати довгі URL, щоб таблиця не розповзалась

# --- 7. User-Agent -----------------------------------------------------------
#
# User-Agent — останнє поле в лапках. Витягуємо його не за номером поля
# (він «плаває» через пробіли всередині), а через роздільник — подвійну лапку.
printf '%s--- Топ-%s User-Agent ---%s\n' "$BOLD" "$TOP_N" "$RESET"
awk -F'"' '{print $6}' "$LOG_FILE" \
    | cut -c1-60 \
    | sort | uniq -c | sort -rn | head -n "$TOP_N" \
    | awk '{ printf "  %6d  ", $1; $1=""; sub(/^ /, ""); print }'
echo
#  awk -F'"' — розділяти рядок за символом ". Тоді поля такі:
#    $2 = "GET /url HTTP/1.1", $4 = referer, $6 = user-agent
#  У останньому awk: $1="" прибирає лічильник, sub() зрізає зайвий пробіл,
#  print друкує решту рядка цілком — бо в User-Agent є пробіли.

printf '%sДалі:%s знайдені IP перевірте в abuseipdb.com, а сам файл\n' "$YELLOW" "$RESET"
printf 'перед відправкою колезі почистіть від персональних даних.\n'
