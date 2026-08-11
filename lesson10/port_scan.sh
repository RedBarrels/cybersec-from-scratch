#!/usr/bin/env bash
#
# port_scan.sh — які порти відкриті на хості
# Курс «Кібербезпека з нуля», заняття №10
#
# Це навчальний сканер. У реальній роботі ви користуватиметесь nmap —
# він швидший, визначає версії сервісів і має NSE-скрипти. Але корисно
# один раз написати сканер самому: тоді зрозуміло, що nmap робить усередині
# і чому SYN-скан потребує root, а connect-скан — ні.
#
# Наш скрипт робить саме connect-скан: повне TCP-рукостискання
# засобами самого bash. Прав root не треба, зате ціль бачить з'єднання
# у своїх логах.
#
# Запуск:
#   ./port_scan.sh localhost                  # типові порти
#   ./port_scan.sh 192.168.1.1 1 1024         # діапазон 1–1024
#   ./port_scan.sh scanme.nmap.org 20 100     # офіційний полігон nmap
#
# ⚠ ЗАКОННІСТЬ: скануйте лише свої системи або ті, на які маєте дозвіл.
# ⚠ Git Bash не підтримує /dev/tcp — під Windows працюйте у WSL.

set -euo pipefail

TARGET="${1:?Вкажіть ціль: $0 localhost [перший_порт] [останній_порт]}"
FIRST_PORT="${2:-}"
LAST_PORT="${3:-}"
TIMEOUT_SEC=1
MAX_JOBS=128

# Валідація цілі за білим списком символів. Ім'я хоста або IP не містить
# нічого, крім літер, цифр, крапок і дефісів. Усе інше — спроба ін'єкції.
if [[ ! "$TARGET" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    echo "Некоректна ціль: $TARGET" >&2
    exit 1
fi

if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
    GREEN=$(tput setaf 2); BOLD=$(tput bold); DIM=$(tput dim); RESET=$(tput sgr0)
else
    GREEN=""; BOLD=""; DIM=""; RESET=""
fi

# --- Які порти перевіряти ----------------------------------------------------
#
# Якщо діапазон не задали — беремо список найцікавіших портів.
# Сканувати всі 65535 має сенс рідко: довго і дуже помітно в логах.
COMMON_PORTS=(21 22 23 25 53 80 110 135 139 143 389 443 445 587 993 995
              1433 1521 2049 2375 3000 3306 3389 5432 5900 6379 8000 8080
              8443 9200 11211 27017)
#  Чому саме ці: 3306/5432/27017/6379/9200/11211 — бази й кеші, які
#  регулярно знаходять відкритими в інтернет без пароля.
#  2375 — Docker API без TLS, це миттєвий root на хості.
#  445/3389 — SMB і RDP, класика ransomware.

if [[ -n "$FIRST_PORT" && -n "$LAST_PORT" ]]; then
    if [[ ! "$FIRST_PORT" =~ ^[0-9]+$ || ! "$LAST_PORT" =~ ^[0-9]+$ ]]; then
        echo "Порти мають бути числами" >&2
        exit 1
    fi
    if (( FIRST_PORT < 1 || LAST_PORT > 65535 || FIRST_PORT > LAST_PORT )); then
        echo "Некоректний діапазон портів" >&2
        exit 1
    fi
    # Наповнюємо масив по одному елементу.
    # Спокусливо написати mapfile -t PORTS < <(seq ...) — коротше в один рядок,
    # але mapfile з'явився в bash 4, а системний bash macOS — 3.2.
    # Цикл нижче працює скрізь.
    PORTS=()
    while read -r p; do
        PORTS+=("$p")
    done < <(seq "$FIRST_PORT" "$LAST_PORT")
    # Фігурні дужки обов'язкові: без них bash не знає, де закінчується
    # ім'я змінної, і в деяких локалях приліплює до нього наступний
    # багатобайтовий символ. Тому тут ще й звичайний дефіс, а не тире.
    RANGE_LABEL="${FIRST_PORT}-${LAST_PORT}"
else
    PORTS=("${COMMON_PORTS[@]}")
    RANGE_LABEL="типові (${#COMMON_PORTS[@]} шт.)"
fi

# --- Як перевіряти порт ------------------------------------------------------
#
# У macOS немає команди timeout (вона з GNU coreutils). Після
# `brew install coreutils` з'являється gtimeout. Перевіряємо обидві.
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_BIN="gtimeout"
fi

check_port() {
    local port="$1"

    if [[ -n "$TIMEOUT_BIN" ]]; then
        # exec 3<>/dev/tcp/... відкриває двонапрямлений сокет на дескрипторі 3.
        # Успішне відкриття = порт відкритий; сокет закриється сам, коли
        # завершиться цей bash -c.
        #
        # ПАСТКА, на якій легко обпектись: не дописуйте сюди другу команду
        # (наприклад "; exec 3<&-"). Код повернення дає ОСТАННЯ команда в
        # рядку, а закриття дескриптора успішне завжди — і тоді скрипт
        # рапортує, що відкриті геть усі порти.
        if "$TIMEOUT_BIN" "$TIMEOUT_SEC" bash -c "exec 3<>/dev/tcp/$TARGET/$port" 2>/dev/null; then
            echo "$port" > "$WORK_DIR/$port"
        fi
    elif command -v nc >/dev/null 2>&1; then
        # Запасний варіант: netcat. -z «просто перевір», -w таймаут.
        if nc -z -w "$TIMEOUT_SEC" "$TARGET" "$port" 2>/dev/null; then
            echo "$port" > "$WORK_DIR/$port"
        fi
    fi
}

# Підпис до відомих портів, щоб результат читався без гуглення.
service_name() {
    case "$1" in
        21) echo "ftp" ;;         22) echo "ssh" ;;
        23) echo "telnet ⚠" ;;    25) echo "smtp" ;;
        53) echo "dns" ;;         80) echo "http" ;;
        110) echo "pop3" ;;       135) echo "msrpc" ;;
        139|445) echo "smb ⚠" ;;  143) echo "imap" ;;
        389) echo "ldap" ;;       443) echo "https" ;;
        587) echo "smtp-sub" ;;   993) echo "imaps" ;;
        995) echo "pop3s" ;;      1433) echo "mssql ⚠" ;;
        1521) echo "oracle ⚠" ;;  2049) echo "nfs ⚠" ;;
        2375) echo "docker-api ⚠⚠" ;;
        3000) echo "node/grafana" ;;
        3306) echo "mysql ⚠" ;;   3389) echo "rdp ⚠" ;;
        5432) echo "postgres ⚠" ;; 5900) echo "vnc ⚠" ;;
        6379) echo "redis ⚠" ;;   8000|8080) echo "http-alt" ;;
        8443) echo "https-alt" ;; 9200) echo "elasticsearch ⚠" ;;
        11211) echo "memcached ⚠" ;; 27017) echo "mongodb ⚠" ;;
        *) echo "" ;;
    esac
}

# --- Сканування --------------------------------------------------------------

WORK_DIR=$(mktemp -d)
chmod 700 "$WORK_DIR"
trap 'rm -rf "$WORK_DIR"' EXIT

printf '%s\n' "${BOLD}=== Сканування портів: $TARGET ===${RESET}"
printf 'Порти  : %s\n' "$RANGE_LABEL"
printf 'Метод  : TCP connect (повне рукостискання, без root)\n\n'

if [[ -z "$TIMEOUT_BIN" ]] && ! command -v nc >/dev/null 2>&1; then
    echo "Немає ні timeout, ні nc. На macOS: brew install coreutils" >&2
    exit 1
fi

started=$(date +%s)

for port in "${PORTS[@]}"; do
    check_port "$port" &
    while (( $(jobs -rp | wc -l) >= MAX_JOBS )); do
        sleep 0.05
    done
done
wait

elapsed=$(( $(date +%s) - started ))

# --- Результат ---------------------------------------------------------------

open_count=$(find "$WORK_DIR" -type f | wc -l | tr -d ' ')

if (( open_count == 0 )); then
    printf 'Відкритих портів не знайдено.\n'
    printf '%sЦе не завжди означає «безпечно»: файрвол міг просто відкинути пакети.%s\n' "$DIM" "$RESET"
else
    printf '%sПОРТ   СЕРВІС%s\n' "$BOLD" "$RESET"
    # ls | sort -n — впорядкувати номери портів як числа
    find "$WORK_DIR" -type f -exec basename {} \; | sort -n | while read -r port; do
        printf '  %s%-5s%s %s\n' "$GREEN" "$port" "$RESET" "$(service_name "$port")"
    done
fi

echo
printf 'Відкрито: %s%s%s   ·   час: %s с\n' "$BOLD" "$open_count" "$RESET" "$elapsed"
echo
printf '%sЩо далі:%s\n' "$BOLD" "$RESET"
printf '  ⚠ поруч із портом означає: сервіс не має дивитись в інтернет\n'
printf '  Версії сервісів і вразливості:  nmap -sV --script vuln %s\n' "$TARGET"