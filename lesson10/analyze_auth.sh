#!/usr/bin/env bash
#
# analyze_auth.sh — хто підбирає паролі до SSH
# Курс «Кібербезпека з нуля», заняття №10
#
# Що робить: читає журнал автентифікації і відповідає на п'ять питань,
# з яких починається розбір будь-якого інциденту з SSH:
#   1. Скільки взагалі було невдалих спроб входу?
#   2. З яких IP-адрес?
#   3. Які імена користувачів перебирали?
#   4. Хто зайшов успішно — і чи є серед них той, хто щойно брутфорсив?
#   5. Хто перевищив поріг і має потрапити в бан?
#
# Запуск:
#   ./analyze_auth.sh                      # знайти журнал автоматично
#   ./analyze_auth.sh samples/auth.log     # конкретний файл
#   ./analyze_auth.sh samples/auth.log 5   # показати топ-5 замість топ-10
#
# Скрипт нічого не змінює в системі. sudo потрібен лише для читання
# справжнього /var/log/auth.log, для тестових файлів — ні.

set -euo pipefail
#  -e            вийти на першій помилці
#  -u            помилка при зверненні до неоголошеної змінної
#  -o pipefail   помилка в будь-якій ланці конвеєра не загубиться

# --- Налаштування -----------------------------------------------------------

LOG_FILE="${1:-}"          # перший аргумент; порожній рядок, якщо не передали
TOP_N="${2:-10}"           # другий аргумент або 10
FAIL_THRESHOLD=10          # від скількох невдалих спроб вважаємо це атакою

# Кольори. tput сам питає термінал, чи вміє він кольори.
# Якщо вивід іде у файл або в pipe — фарбувати не треба, вийде сміття.
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
    RED=$(tput setaf 1); YELLOW=$(tput setaf 3); GREEN=$(tput setaf 2)
    BOLD=$(tput bold);   RESET=$(tput sgr0)
else
    RED=""; YELLOW=""; GREEN=""; BOLD=""; RESET=""
fi
#  [[ -t 1 ]]  — «стандартний вивід (дескриптор 1) — це термінал?»

# --- Крок 1. Знайти джерело логів -------------------------------------------
#
# У 2026 році однієї відповіді «дивись /var/log/auth.log» уже недостатньо:
#   Ubuntu           — rsyslog на місці, /var/log/auth.log є
#   Debian 12+       — rsyslog за замовчуванням не ставиться, є лише journalctl
#   RHEL/Fedora      — /var/log/secure або journalctl
#   macOS            — свій формат, читається через `log show`
# Тому спочатку шукаємо файл, а якщо його немає — вивантажуємо журнал systemd.

TMP_LOG=""                 # сюди запишемо шлях, якщо доведеться робити тимчасовий файл
LOG_LABEL=""               # як показати джерело у звіті

cleanup() {
    # Прибираємо за собою в будь-якому разі: і при нормальному завершенні,
    # і при Ctrl+C, і при помилці. Це те, що робить trap ... EXIT.
    [[ -n "$TMP_LOG" && -f "$TMP_LOG" ]] && rm -f "$TMP_LOG"
    return 0
}
trap cleanup EXIT

find_log() {
    # Якщо шлях передали аргументом — використовуємо його і більше не гадаємо.
    if [[ -n "$LOG_FILE" ]]; then
        [[ -r "$LOG_FILE" ]] || { echo "Не можу прочитати: $LOG_FILE" >&2; exit 1; }
        return 0
    fi

    local candidate
    for candidate in /var/log/auth.log /var/log/secure; do
        if [[ -r "$candidate" ]]; then
            LOG_FILE="$candidate"
            return 0
        fi
    done

    # Файлів немає — пробуємо systemd-журнал.
    if command -v journalctl >/dev/null 2>&1; then
        TMP_LOG=$(mktemp)                       # безпечне ім'я, яке не вгадати
        chmod 600 "$TMP_LOG"                    # читати може лише власник
        # 2>/dev/null — щоб скарги про брак прав не потрапили у вибірку
        if journalctl -u ssh -u sshd --since "24 hours ago" --no-pager > "$TMP_LOG" 2>/dev/null &&
           [[ -s "$TMP_LOG" ]]; then            # -s = файл існує і не порожній
            LOG_FILE="$TMP_LOG"
            LOG_LABEL="systemd journal (останні 24 год)"
            return 0
        fi
    fi

    echo "Не знайшов журнал автентифікації." >&2
    echo "Передайте файл явно:  $0 samples/auth.log" >&2
    echo "Або згенеруйте тестовий:  ./make_samples.sh" >&2
    exit 1
}

find_log
[[ -n "$LOG_LABEL" ]] || LOG_LABEL="$LOG_FILE"

# --- Крок 2. Витягнути невдалі спроби ---------------------------------------
#
# Рядок sshd виглядає так:
#   Aug  9 03:14:07 web01 sshd[2211]: Failed password for invalid user admin \
#       from 203.0.113.7 port 51314 ssh2
#
# Поля awk рахує з кінця: $NF = "ssh2", $(NF-1) = номер порту,
# $(NF-2) = "port", $(NF-3) = IP-адреса. Рахунок з кінця надійніший, ніж
# з початку, бо на початку рядка може бути різна кількість полів
# (ім'я хоста з пробілом, різний формат дати, префікс від journalctl).

failed_lines=$(grep -F "Failed password" "$LOG_FILE" || true)
#  -F      шукати як звичайний текст, а не регулярний вираз (швидше й без сюрпризів)
#  || true — grep повертає код 1, якщо нічого не знайшов. Під set -e це
#            вбило б скрипт. «Нічого не знайдено» — нормальний результат,
#            а не помилка, тому глушимо код повернення.

if [[ -z "$failed_lines" ]]; then
    total_failed=0
else
    total_failed=$(printf '%s\n' "$failed_lines" | wc -l | tr -d ' ')
fi

# --- Крок 3. Звіт -----------------------------------------------------------

printf '%s\n' "${BOLD}=== Аналіз журналу автентифікації ===${RESET}"
printf 'Джерело : %s\n' "$LOG_LABEL"
printf 'Рядків  : %s\n' "$(wc -l < "$LOG_FILE" | tr -d ' ')"
printf 'Невдалих спроб входу: %s%s%s\n\n' "$BOLD" "$total_failed" "$RESET"

if (( total_failed == 0 )); then
    printf '%sНевдалих спроб немає.%s\n' "$GREEN" "$RESET"
    exit 0
fi

# --- 3.1 Топ IP-адрес --------------------------------------------------------
#
# Конвеєр sort | uniq -c | sort -rn — головна ідіома роботи з логами.
#   sort      згрупувати однакові рядки поруч
#   uniq -c   схлопнути й порахувати (uniq бачить лише сусідні дублікати!)
#   sort -rn  відсортувати за числом, у спадному порядку
printf '%s--- Топ-%s IP за кількістю невдалих спроб ---%s\n' "$BOLD" "$TOP_N" "$RESET"
printf '%s\n' "$failed_lines" \
    | awk '{print $(NF-3)}' \
    | sort | uniq -c | sort -rn | head -n "$TOP_N" \
    | while read -r count ip; do
        # read -r — не з'їдати зворотні слеші. Пишемо -r завжди.
        if (( count >= FAIL_THRESHOLD )); then
            printf '  %s%6d  %-16s ← понад поріг (%d)%s\n' "$RED" "$count" "$ip" "$FAIL_THRESHOLD" "$RESET"
        else
            printf '  %6d  %s\n' "$count" "$ip"
        fi
      done
echo

# --- 3.2 Топ імен користувачів ----------------------------------------------
#
# Тут два формати в одному файлі:
#   ... for invalid user admin from IP ...   (користувача в системі немає)
#   ... for deploy from IP ...               (користувач існує)
# Не рахуємо поля вручну, а знаходимо слово "for" і беремо те, що після нього.
# Якщо далі йде "invalid user" — пропускаємо ці два слова.
# Такий розбір не ламається, коли формат рядка трохи змінюється.
printf '%s--- Топ-%s імен, які перебирали ---%s\n' "$BOLD" "$TOP_N" "$RESET"
printf '%s\n' "$failed_lines" \
    | awk '{
        for (i = 1; i < NF; i++) {
            if ($i == "for") {
                if ($(i+1) == "invalid" && $(i+2) == "user") print $(i+3)
                else print $(i+1)
                break        # знайшли — далі рядок не читаємо
            }
        }
      }' \
    | sort | uniq -c | sort -rn | head -n "$TOP_N" \
    | awk '{printf "  %6d  %s\n", $1, $2}'
echo

# --- 3.3 Успішні входи -------------------------------------------------------
printf '%s--- Успішні входи ---%s\n' "$BOLD" "$RESET"
accepted=$(grep -F "Accepted " "$LOG_FILE" || true)
if [[ -z "$accepted" ]]; then
    printf '  немає\n'
else
    # Той самий підхід: шукаємо ключові слова "for" і "from"
    printf '%s\n' "$accepted" \
        | awk '{
            user = "?"; ip = "?"
            for (i = 1; i < NF; i++) {
                if ($i == "for")  user = $(i+1)
                if ($i == "from") ip   = $(i+1)
            }
            print user, ip
          }' \
        | sort | uniq -c | sort -rn \
        | awk '{printf "  %6d  %-12s з %s\n", $1, $2, $3}'
fi
echo

# --- 3.4 Головне: хто брутфорсив і таки зайшов ------------------------------
#
# Це найцінніший рядок у всьому скрипті. Сама по собі невдала спроба —
# фоновий шум інтернету. Невдалі спроби + успішний вхід з тієї самої
# адреси — це вже підозра на скомпрометований обліковий запис.
printf '%s--- ⚠ IP, які і брутфорсили, і зайшли успішно ---%s\n' "$BOLD" "$RESET"
bad_ips=$(printf '%s\n' "$failed_lines" | awk '{print $(NF-3)}' | sort -u)
good_ips=$(printf '%s\n' "$accepted"    | awk '{for (i=1; i<=NF; i++) if ($i == "from") print $(i+1)}' | sort -u)

# comm -12 показує рядки, присутні в обох відсортованих списках (перетин).
overlap=$(comm -12 <(printf '%s\n' "$bad_ips") <(printf '%s\n' "$good_ips") || true)
#  <(...) — підстановка процесу: вивід команди подається як файл.

if [[ -z "$overlap" ]]; then
    printf '  %sнемає — це добре%s\n' "$GREEN" "$RESET"
else
    printf '%s\n' "$overlap" | while read -r ip; do
        [[ -n "$ip" ]] && printf '  %s%s%s — перевірити цей обліковий запис вручну\n' "$RED$BOLD" "$ip" "$RESET"
    done
fi
echo

# --- 3.5 Готовий список для блокування --------------------------------------
printf '%s--- Кандидати на блокування (>= %d спроб) ---%s\n' "$BOLD" "$FAIL_THRESHOLD" "$RESET"
printf '%s\n' "$failed_lines" \
    | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn \
    | awk -v t="$FAIL_THRESHOLD" '$1 >= t {print $2}' \
    | while read -r ip; do
        # Команду ТІЛЬКИ друкуємо, а не виконуємо. Скрипт аналізу не повинен
        # сам міняти firewall: одна помилка в парсингу — і ви забанили себе.
        printf '  sudo ufw deny from %s\n' "$ip"
      done
echo
printf '%sПідказка:%s перевірте адреси через abuseipdb.com перед блокуванням.\n' "$YELLOW" "$RESET"
