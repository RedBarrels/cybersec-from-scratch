#!/usr/bin/env bash
#
# secret_scan.sh — пошук секретів на диску за допомогою TruffleHog
# Курс «Кібербезпека з нуля», заняття №10
#
# ЩО ЦЕ ВЗАГАЛІ ЗА ЗАДАЧА
# -----------------------------------------------------------------------------
# Токени, ключі й паролі осідають у файлах непомітно: .env поруч із проєктом,
# ~/.aws/credentials, kubeconfig, дамп бази з паролями всередині, лог із
# заголовком Authorization, старий скрипт деплою з вписаним ключем.
# Людина про них забуває, а бекап, синхронізація в хмару чи вкрадений ноутбук —
# ні. Тому «що в мене лежить на диску» — стандартне питання аудиту.
#
# TruffleHog вміє дві речі, яких немає у звичайного grep:
#   1) знає ~800 форматів облікових даних (AWS, GitHub, Slack, Stripe, SSH-ключі
#      і так далі) — не треба вигадувати регулярки самому;
#   2) вміє ПЕРЕВІРИТИ, чи ключ ще живий: звертається до API постачальника.
#      Це відсіює тонни мертвих знахідок.
#
# Цей скрипт — обгортка: він запускає TruffleHog з безпечними налаштуваннями,
# збирає результат і робить із нього читабельний звіт.
#
#
# ВСТАНОВЛЕННЯ TRUFFLEHOG
# -----------------------------------------------------------------------------
# Варіант 1 — macOS, Homebrew (найпростіший):
#     brew install trufflehog
#
# Варіант 2 — Linux / macOS, офіційний інсталятор:
#     curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
#       | sh -s -- -b /usr/local/bin
#
#     ⚠ Це той самий патерн «curl | sh», про який ми говорили на занятті про
#       supply chain: ви виконуєте чужий скрипт із правами свого користувача.
#       Правильно — спершу прочитати його, потім запускати:
#         curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh -o install.sh
#         less install.sh
#         sh install.sh -b /usr/local/bin
#
# Варіант 3 — Docker (нічого не ставимо в систему):
#     docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest \
#         filesystem /pwd --no-update
#     На Apple Silicon додайте --platform linux/arm64
#
# Варіант 4 — з вихідників, якщо вже є Go:
#     go install github.com/trufflesecurity/trufflehog/v3@latest
#
# Варіант 5 — Kali Linux: пакет уже в репозиторії
#     sudo apt install trufflehog
#
# Варіант 6 — Windows: працюйте у WSL і ставте як на Linux.
#
# Перевірка після встановлення:
#     trufflehog --version        # має бути 3.x
#
#
# ЗАПУСК
# -----------------------------------------------------------------------------
#     ./secret_scan.sh                    # просканувати поточний каталог
#     ./secret_scan.sh ~/projects         # конкретний каталог
#     ./secret_scan.sh ~/projects --verify  # ще й перевірити, чи ключі живі
#     ./secret_scan.sh /                  # весь диск (довго, краще вночі)
#
# Скрипт лише читає файли. Він нічого не змінює, не видаляє й не відправляє
# знайдені секрети нікуди — крім випадку --verify, див. попередження нижче.

set -euo pipefail

# --- Аргументи ---------------------------------------------------------------

SCAN_PATH="."
VERIFY=0            # 0 = не перевіряти живучість ключів (офлайн, за замовчуванням)
KEEP_JSON=1         # зберігати сирий JSON як доказ для тікета

# Простий розбір аргументів. Проходимо по всіх, поки вони є.
while (( $# > 0 )); do
    case "$1" in
        --verify)   VERIFY=1 ;;
        --no-json)  KEEP_JSON=0 ;;
        -h|--help)
            # sed -n '/^# ЗАПУСК/,/^set -e/p' витягнув би довідку з коментарів,
            # але простіше й надійніше написати її явно.
            printf 'Використання: %s [шлях] [--verify] [--no-json]\n' "$0"
            exit 0 ;;
        -*)
            echo "Невідомий аргумент: $1" >&2
            exit 1 ;;
        *)
            SCAN_PATH="$1" ;;
    esac
    shift        # прибрати оброблений аргумент, $2 стає $1
done

[[ -e "$SCAN_PATH" ]] || { echo "Шлях не існує: $SCAN_PATH" >&2; exit 1; }
[[ -r "$SCAN_PATH" ]] || { echo "Немає прав на читання: $SCAN_PATH" >&2; exit 1; }

# --- Кольори -----------------------------------------------------------------

if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
    RED=$(tput setaf 1); YELLOW=$(tput setaf 3); GREEN=$(tput setaf 2)
    BOLD=$(tput bold);   DIM=$(tput dim); RESET=$(tput sgr0)
else
    RED=""; YELLOW=""; GREEN=""; BOLD=""; DIM=""; RESET=""
fi

# --- Перевірка, що TruffleHog взагалі є --------------------------------------

if ! command -v trufflehog >/dev/null 2>&1; then
    echo "TruffleHog не знайдено." >&2
    echo >&2
    echo "Встановіть одним зі способів:" >&2
    echo "  macOS:  brew install trufflehog" >&2
    echo "  Linux:  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin" >&2
    echo "  Docker: docker run --rm -v \"\$PWD:/pwd\" trufflesecurity/trufflehog:latest filesystem /pwd" >&2
    exit 1
fi

# --- Тимчасові файли ---------------------------------------------------------

WORK_DIR=$(mktemp -d)
chmod 700 "$WORK_DIR"          # у цих файлах будуть секрети — тільки для власника
trap 'rm -rf "$WORK_DIR"' EXIT

RAW_JSON="$WORK_DIR/findings.ndjson"
EXCLUDES="$WORK_DIR/excludes.txt"

# --- Що не скануємо ----------------------------------------------------------
#
# Без винятків скан каталогу з проєктами перетворюється на скан node_modules.
# Файл винятків — це список регулярних виразів, по одному на рядок.
# TruffleHog приймає його через -x / --exclude-paths.
cat > "$EXCLUDES" <<'EOF'
node_modules/
\.venv/
venv/
site-packages/
\.git/objects/
\.cache/
\.npm/
\.gradle/
Library/Caches/
target/debug/
target/release/
dist/
build/
\.min\.js$
\.(png|jpe?g|gif|ico|svg|webp|mp4|mp3|zip|gz|bz2|xz|dmg|iso|pdf)$
secret-scan-[0-9]+-[0-9]+\.ndjson$
EOF
#  <<'EOF' — heredoc. Лапки навколо EOF означають «не розкривати змінні
#  всередині», тому $ і \ потрапляють у файл як є. Без лапок bash спробував
#  би підставити змінні і зіпсував би регулярки.
#
#  Останній рядок — не дрібниця. Скрипт зберігає звіт із секретами поруч,
#  і на другому запуску сканер знаходить... власний звіт. Кількість знахідок
#  подвоюється на кожному прогоні. Я на це наступив, поки писав скрипт.

# --- Формуємо команду --------------------------------------------------------
#
# Аргументи збираємо в масив, а не в рядок. Рядок «розсипався» б по пробілах
# і зламався на шляху з пробілом (а ~/Library/Application Support — саме такий).
TH_ARGS=(filesystem "$SCAN_PATH"
         --json                 # машинний вивід, по одному JSON-об'єкту на рядок
         --no-update            # не лізти в мережу за оновленням самого себе
         --exclude-paths "$EXCLUDES"
         --no-color)            # ми фарбуємо звіт самі

if (( VERIFY == 0 )); then
    TH_ARGS+=(--no-verification)
fi

# Показуємо абсолютний шлях, щоб у звіті було видно, що саме сканували.
# realpath є не скрізь, а readlink -f на macOS поводиться інакше, ніж у Linux —
# тому робимо це переносимо, через cd + pwd у підоболонці.
if [[ -d "$SCAN_PATH" ]]; then
    ABS_PATH=$(cd "$SCAN_PATH" && pwd)
else
    ABS_PATH="$(cd "$(dirname "$SCAN_PATH")" && pwd)/$(basename "$SCAN_PATH")"
fi

printf '%s\n' "${BOLD}=== Пошук секретів у файлах ===${RESET}"
printf 'Каталог  : %s\n' "$ABS_PATH"
printf 'Версія   : %s\n' "$(trufflehog --version 2>&1 | head -1)"

if (( VERIFY == 1 )); then
    # ⚠ Найважливіше попередження в усьому скрипті.
    # Перевірка означає, що TruffleHog візьме знайдений ключ і спробує ним
    # автентифікуватись у AWS, GitHub, Slack тощо. Тобто:
    #   – з хоста піде вихідний трафік до сторонніх API;
    #   – у логах постачальника з'явиться спроба входу вашим ключем;
    #   – на закритому контурі це може бути порушенням політики.
    # Тому режим увімкнено ЯВНО прапорцем, а не за замовчуванням.
    printf 'Режим    : %sз перевіркою — ключі підуть у зовнішні API%s\n' "$YELLOW" "$RESET"
else
    printf 'Режим    : %sофлайн (без звернень до зовнішніх API)%s\n' "$DIM" "$RESET"
fi
printf '\n%sСкануємо...%s\n' "$DIM" "$RESET"

# --- Запуск ------------------------------------------------------------------
#
# stderr TruffleHog — це його власні логи, у звіт вони не потрібні.
# Код повернення ловимо вручну: під set -e ненульовий код завершив би скрипт,
# а нам треба показати звіт у будь-якому разі.
scan_rc=0
trufflehog "${TH_ARGS[@]}" > "$RAW_JSON" 2>"$WORK_DIR/scan.log" || scan_rc=$?

if (( scan_rc != 0 )); then
    printf '%sTruffleHog завершився з кодом %d. Останні рядки логу:%s\n' "$YELLOW" "$scan_rc" "$RESET"
    tail -5 "$WORK_DIR/scan.log" >&2
fi

# --- Розбір результату -------------------------------------------------------
#
# Кожен рядок RAW_JSON — окремий JSON-об'єкт (формат NDJSON). Нас цікавлять
# чотири поля:
#   DetectorName — що це за тип ключа (AWS, Github, Slack...)
#   Verified     — true, якщо ключ підтверджено живим
#   ...Filesystem.file — у якому файлі
#   ...Filesystem.line — у якому рядку
#
# Правильний інструмент для JSON — jq. Але його немає «з коробки» ні в macOS,
# ні в мінімальних образах, тому робимо розбір на awk: маленька функція
# витягує значення за ім'ям ключа. Для навчального звіту цього досить;
# у продакшн-пайплайні ставте jq і не вигадуйте.
awk '
function field(s, key,   re, p, rest) {
    re = "\"" key "\":\""
    p = index(s, re)
    if (p == 0) return ""
    rest = substr(s, p + length(re))
    return substr(rest, 1, index(rest, "\"") - 1)
}
{
    det  = field($0, "DetectorName")
    file = field($0, "file")
    if (det == "") next          # службові рядки логу пропускаємо

    # Verified — булеве значення, тому без лапок: шукаємо точний підрядок.
    ver = (index($0, "\"Verified\":true") > 0) ? "VERIFIED" : "unverified"

    # Рядок у файлі — теж число без лапок.
    line = "?"
    if (match($0, /"line":[0-9]+/)) {
        line = substr($0, RSTART + 7, RLENGTH - 7)
    }

    # Друкуємо через табуляцію: далі bash зручно читати такий формат.
    # Саме значення секрету (поле Raw) НЕ друкуємо — див. коментар нижче.
    printf "%s\t%s\t%s\t%s\n", ver, det, file, line
}' "$RAW_JSON" > "$WORK_DIR/parsed.tsv"

# ⚠ Чому звіт не містить самих секретів.
# Звіт живе довше за інцидент: він потрапляє у тікет, у чат, у пошту, в архів
# на файловій шарі. Якщо в ньому лежить сам ключ — ви щойно скопіювали витік
# у ще п'ять місць. Тому в звіті лише координати: тип, файл, рядок.
# Сам ключ людина побачить, відкривши файл, і одразу піде його ротувати.

total=$(awk 'END {print NR}' "$WORK_DIR/parsed.tsv")
verified=$(grep -c '^VERIFIED' "$WORK_DIR/parsed.tsv" || true)

# --- Звіт --------------------------------------------------------------------

echo
if (( total == 0 )); then
    printf '%sСекретів не знайдено.%s\n' "$GREEN" "$RESET"
    printf '\n%sЦе не гарантія. TruffleHog знає близько 800 форматів, але\n' "$DIM"
    printf 'саморобний токен «PASSWORD=qwerty123» під жоден із них не підпадає.%s\n' "$RESET"
    exit 0
fi

if (( verified > 0 )); then
    printf '%s%sЗНАЙДЕНО %d ЖИВИХ КЛЮЧІВ%s — це інцидент, а не знахідка.\n' \
        "$RED" "$BOLD" "$verified" "$RESET"
fi
printf 'Усього знахідок: %s%d%s (живих: %d)\n\n' "$BOLD" "$total" "$RESET" "$verified"

# 1. Розбивка за типом ключа
printf '%s--- За типом ---%s\n' "$BOLD" "$RESET"
cut -f2 "$WORK_DIR/parsed.tsv" | sort | uniq -c | sort -rn \
    | awk '{printf "  %5d  %s\n", $1, $2}'
echo

# 2. Файли-рекордсмени
printf '%s--- Топ-10 файлів ---%s\n' "$BOLD" "$RESET"
cut -f3 "$WORK_DIR/parsed.tsv" | sort | uniq -c | sort -rn | head -10 \
    | while read -r count file; do
        printf '  %5d  %s\n' "$count" "$file"
      done
echo

# 3. Живі ключі — окремим списком, це найвищий пріоритет
if (( verified > 0 )); then
    printf '%s--- ЖИВІ КЛЮЧІ (ротувати негайно) ---%s\n' "$RED$BOLD" "$RESET"
    grep '^VERIFIED' "$WORK_DIR/parsed.tsv" \
        | while IFS=$'\t' read -r _ det file line; do
            printf '  %s%-14s%s %s:%s\n' "$RED" "$det" "$RESET" "$file" "$line"
          done
    #  IFS=$'\t' перед read — розділяти саме по табуляції.
    #  Інакше read поріже рядок ще й по пробілах, і шлях із пробілом розвалиться.
    echo
fi

# 4. Решта знахідок
printf '%s--- Неперевірені знахідки ---%s\n' "$BOLD" "$RESET"
grep -v '^VERIFIED' "$WORK_DIR/parsed.tsv" | head -25 \
    | while IFS=$'\t' read -r _ det file line; do
        printf '  %s%-14s%s %s:%s\n' "$YELLOW" "$det" "$RESET" "$file" "$line"
      done

remaining=$(( total - verified - 25 ))
if (( remaining > 0 )); then
    printf '  %s... і ще %d — дивіться повний JSON%s\n' "$DIM" "$remaining" "$RESET"
fi
echo

# --- Сирий JSON як доказ -----------------------------------------------------

if (( KEEP_JSON == 1 )); then
    out="secret-scan-$(date +%Y%m%d-%H%M%S).ndjson"
    # umask 077 → новий файл створиться з правами 600, і жоден інший
    # користувач системи його не прочитає. Встановлюємо в підоболонці ( ),
    # щоб не змінювати umask для решти скрипта.
    ( umask 077; cp "$RAW_JSON" "$out" )
    printf '%sПовний результат:%s %s (права 600)\n' "$DIM" "$RESET" "$out"
    printf '%sУ ньому Є самі секрети. Не комітьте його і не кладіть у тікет.%s\n' "$YELLOW" "$RESET"
    echo
fi

# --- Що робити далі ----------------------------------------------------------

printf '%sПорядок дій при знайденому ключі:%s\n' "$BOLD" "$RESET"
printf '  1. Ротувати ключ. Спершу ротація, потім усе інше.\n'
printf '  2. Перевірити логи постачальника: чи ним уже користувались.\n'
printf '  3. Прибрати з файлу — і, якщо це git, з ІСТОРІЇ теж:\n'
printf '     %sgit log --all -S "фрагмент" --oneline%s\n' "$DIM" "$RESET"
printf '     видалення з історії: git filter-repo або BFG Repo-Cleaner\n'
printf '  4. Поставити на майбутнє: pre-commit hook + сканер у CI.\n'
printf '  5. Перенести секрет у сховище: 1Password, Vault, SOPS,\n'
printf '     GitHub Actions secrets — будь-що, крім файлу поруч із кодом.\n'
echo
printf '%s%s%s\n' "$DIM" "Видалити ключ із файлу недостатньо: він лишається в git-історії," "$RESET"
printf '%s%s%s\n' "$DIM" "у бекапах і, ймовірно, вже в чиємусь кеші. Ротація обов'язкова." "$RESET"
echo
printf '%sПеревірити git-історію проєкту:%s\n' "$BOLD" "$RESET"
printf '  trufflehog git file://. --results=verified\n'

# Код повернення: 1, якщо щось знайшли. Придатне для CI та cron.
(( total == 0 ))
