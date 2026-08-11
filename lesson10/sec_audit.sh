#!/usr/bin/env bash
#
# sec_audit.sh — базовий аудит безпеки робочої станції / сервера
# Курс «Кібербезпека з нуля», заняття №10
#
# Що робить: проходить список перевірок, які покривають найчастіші
# реальні проблеми — вимкнений файрвол, вхід root по SSH, відсутнє
# шифрування диска, оновлення, що не встановлюються роками.
#
# Скрипт READ-ONLY: він нічого не змінює і не потребує sudo.
# Частина перевірок без sudo недоступна — тоді чесно пишемо SKIP,
# а не вигадуємо PASS. Аудит, який мовчки пропускає перевірку і каже
# «все добре», гірший за відсутність аудиту.
#
# Запуск:
#   ./sec_audit.sh                 # звіт у термінал
#   ./sec_audit.sh | tee audit.txt # і на екран, і у файл
#
# Код повернення: 0 — жодного FAIL, 1 — є хоча б один FAIL.
# Саме на цьому будується інтеграція з CI: пайплайн падає на FAIL.

set -uo pipefail
#  Тут свідомо БЕЗ -e. Аудит має пройти всі перевірки до кінця, навіть
#  якщо якась команда завершилась помилкою. Замість -e ми перевіряємо
#  коди повернення вручну там, де це важливо.

# --- Кольори та лічильники ---------------------------------------------------

if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
    RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4); BOLD=$(tput bold); DIM=$(tput dim); RESET=$(tput sgr0)
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; DIM=""; RESET=""
fi

pass_count=0
fail_count=0
warn_count=0
skip_count=0

# ПАСТКА, через яку ламаються всі україномовні звіти:
# printf '%-40s' вирівнює по БАЙТАХ, а кирилиця в UTF-8 займає 2 байти на
# літеру — колонки «пливуть». Конструкція ${#рядок} рахує символи лише
# тоді, коли локаль UTF-8; у CI локаль часто C, і там теж будуть байти.
#
# Рахуємо символи незалежно від локалі: у UTF-8 «продовжувальні» байти
# мають старші біти 10xxxxxx (діапазон \200–\277). Викидаємо їх — і
# лишається рівно по одному байту на символ.
utf8_len() {
    LC_ALL=C printf '%s' "$1" | LC_ALL=C tr -d '\200-\277' | LC_ALL=C wc -c | tr -d ' '
}

pad() {
    local text="$1" width="$2" len
    len=$(utf8_len "$text")
    printf '%s' "$text"
    while (( len < width )); do
        printf ' '
        len=$((len + 1))
    done
}

# Один друкар для всіх перевірок — так вивід залишається однаковим,
# і не треба повторювати форматування у двадцяти місцях.
result() {
    local status="$1" label="$2" detail="${3:-}"
    local tag color

    case "$status" in
        PASS) tag="PASS"; color="$GREEN";  pass_count=$((pass_count + 1)) ;;
        FAIL) tag="FAIL"; color="$RED";    fail_count=$((fail_count + 1)) ;;
        WARN) tag="WARN"; color="$YELLOW"; warn_count=$((warn_count + 1)) ;;
        SKIP) tag="SKIP"; color="$DIM";    skip_count=$((skip_count + 1)) ;;
        *)    tag="????"; color="" ;;
    esac

    printf '  %s[%s]%s ' "$color" "$tag" "$RESET"
    pad "$label" 40
    if [[ "$status" == "PASS" || "$status" == "SKIP" ]]; then
        printf ' %s%s%s\n' "$DIM" "$detail" "$RESET"
    else
        printf ' %s\n' "$detail"
    fi
}

section() {
    printf '\n%s%s%s\n' "$BOLD$BLUE" "$1" "$RESET"
}

have() { command -v "$1" >/dev/null 2>&1; }
#  Коротка функція-хелпер: have ufw → «чи є в системі команда ufw».

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
#  Привести до нижнього регістру. У bash 4+ для цього є ${var,,},
#  але системний bash macOS — версії 3.2, і там такого синтаксису немає.
#  Скрипт має працювати на найбіднішому середовищі, тому tr.

# --- Визначення платформи ----------------------------------------------------

case "$(uname -s)" in
    Linux*)
        # WSL зсередини виглядає як Linux, але поводиться інакше:
        # своя NAT-мережа, часто немає systemd, файрвол Windows не видно.
        if grep -qi microsoft /proc/version 2>/dev/null; then
            OS="wsl"
        else
            OS="linux"
        fi ;;
    Darwin*) OS="macos" ;;
    *) echo "Непідтримувана система: $(uname -s)" >&2; exit 1 ;;
esac

os_name="$(uname -s) $(uname -r)"
if [[ "$OS" == "macos" ]]; then
    os_name="macOS $(sw_vers -productVersion 2>/dev/null || echo '?')"
elif [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    # SC1091 = «не можу перевірити файл, якого немає на моїй машині».
    # Тут це нормально: /etc/os-release є на цільовій системі.
    os_name="$( . /etc/os-release && echo "$PRETTY_NAME" )"
fi

printf '%s\n' "${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
printf '%s\n' "${BOLD}║  Аудит безпеки системи                               ║${RESET}"
printf '%s\n' "${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
printf 'Хост      : %s\n' "$(hostname)"
printf 'Платформа : %s (%s)\n' "$os_name" "$OS"
printf 'Дата      : %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
printf 'Користувач: %s (uid=%s)\n' "$(id -un)" "$(id -u)"

# ============================================================================
# 1. СЕРЕДОВИЩЕ
# ============================================================================
section "1. Середовище"

bash_major="${BASH_VERSINFO[0]}"
if (( bash_major >= 4 )); then
    result PASS "Версія bash" "$BASH_VERSION"
else
    # macOS досі постачає bash 3.2 (2007) через ліцензію GPLv3.
    # Масиви-словники, ${var^^}, mapfile — нічого з цього там немає.
    result WARN "Версія bash" "$BASH_VERSION — старий; brew install bash"
fi

if (( EUID == 0 )); then
    result WARN "Запуск від root" "аудит краще робити від звичайного користувача"
else
    result PASS "Запуск від звичайного користувача" "uid=$EUID"
fi

# ============================================================================
# 2. МЕРЕЖЕВИЙ ПЕРИМЕТР
# ============================================================================
section "2. Мережевий периметр"

check_firewall() {
    if [[ "$OS" == "macos" ]]; then
        local state
        state=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo "")
        case "$state" in
            1) result PASS "Application Firewall" "увімкнено" ;;
            2) result PASS "Application Firewall" "увімкнено (блокує всі вхідні)" ;;
            0) result FAIL "Application Firewall" "вимкнено" ;;
            *) result SKIP "Application Firewall" "не вдалось прочитати стан" ;;
        esac
        return
    fi

    if [[ "$OS" == "wsl" ]]; then
        result SKIP "Файрвол" "у WSL за периметр відповідає Windows Defender Firewall"
        return
    fi

    if have ufw; then
        if ufw status 2>/dev/null | grep -qi "^Status: active"; then
            result PASS "Файрвол (ufw)" "активний"
        else
            # Без sudo ufw status часто нічого не каже — це не те саме,
            # що «вимкнено». Тому WARN, а не FAIL.
            result WARN "Файрвол (ufw)" "неактивний або потрібен sudo"
        fi
    elif have firewall-cmd; then
        if firewall-cmd --state 2>/dev/null | grep -q running; then
            result PASS "Файрвол (firewalld)" "активний"
        else
            result FAIL "Файрвол (firewalld)" "не запущено"
        fi
    elif have nft; then
        if [[ -n "$(nft list ruleset 2>/dev/null)" ]]; then
            result PASS "Файрвол (nftables)" "правила є"
        else
            result WARN "Файрвол (nftables)" "правил не видно (можливо, потрібен sudo)"
        fi
    else
        result SKIP "Файрвол" "жодного відомого інструмента не знайдено"
    fi
}
check_firewall

# Відкриті порти. ss — сучасна заміна netstat у Linux; на macOS — lsof.
check_listening() {
    local count=""
    if have ss; then
        count=$(ss -H -tln 2>/dev/null | wc -l | tr -d ' ')
    elif have netstat; then
        count=$(netstat -an 2>/dev/null | grep -c "LISTEN" || true)
    elif have lsof; then
        count=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
    fi

    if [[ -z "$count" ]]; then
        result SKIP "Відкриті TCP-порти" "немає ss / netstat / lsof"
    elif (( count > 15 )); then
        result WARN "Відкриті TCP-порти" "$count — перевірте, чи всі потрібні"
    else
        result PASS "Відкриті TCP-порти" "$count"
    fi
}
check_listening

# ============================================================================
# 3. ВІДДАЛЕНИЙ ДОСТУП (SSH)
# ============================================================================
section "3. Віддалений доступ"

check_ssh() {
    local cfg="/etc/ssh/sshd_config"
    if [[ ! -r "$cfg" ]]; then
        result SKIP "Конфігурація SSH" "$cfg недоступний (потрібен sudo або sshd не встановлено)"
        return
    fi

    # Читаємо не лише основний файл, а й /etc/ssh/sshd_config.d/*.conf —
    # у сучасних дистрибутивах реальні налаштування часто саме там,
    # і саме на цьому провалюються саморобні аудити.
    local all_cfg
    all_cfg=$(cat "$cfg" /etc/ssh/sshd_config.d/*.conf 2>/dev/null)

    # grep -E: рядок починається з ключа (можливі пробіли), далі значення.
    # Закоментовані рядки (#) не рахуються — це значення за замовчуванням.
    local root_login
    root_login=$(printf '%s\n' "$all_cfg" | grep -Ei '^[[:space:]]*PermitRootLogin' | tail -1 | awk '{print $2}')
    #  tail -1 — якщо ключ трапився кілька разів, sshd бере... насправді
    #  ПЕРШЕ значення. Тут беремо останнє свідомо: так помітніше, що
    #  в конфізі дубль. Для точного значення завжди звіряйтесь із
    #  `sshd -T`, який показує реальну діючу конфігурацію.

    case "$(lower "$root_login")" in
        ""|yes)    result FAIL "SSH: вхід від root" "${root_login:-yes (за замовчуванням)}" ;;
        no)        result PASS "SSH: вхід від root" "заборонено" ;;
        prohibit-password|without-password) result PASS "SSH: вхід від root" "тільки по ключу" ;;
        *)         result WARN "SSH: вхід від root" "$root_login" ;;
    esac

    local pass_auth
    pass_auth=$(printf '%s\n' "$all_cfg" | grep -Ei '^[[:space:]]*PasswordAuthentication' | tail -1 | awk '{print $2}')
    case "$(lower "$pass_auth")" in
        no)  result PASS "SSH: автентифікація паролем" "вимкнено (тільки ключі)" ;;
        yes) result WARN "SSH: автентифікація паролем" "увімкнено — брутфорс можливий" ;;
        *)   result WARN "SSH: автентифікація паролем" "не задано явно (типово yes)" ;;
    esac
}
check_ssh

# ============================================================================
# 4. ОНОВЛЕННЯ
# ============================================================================
section "4. Оновлення"

check_updates() {
    if [[ "$OS" == "macos" ]]; then
        local auto
        auto=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "")
        if [[ "$auto" == "1" ]]; then
            result PASS "Автоматична перевірка оновлень" "увімкнено"
        else
            result WARN "Автоматична перевірка оновлень" "вимкнено або невідомо"
        fi
        return
    fi

    if have apt-get; then
        # apt list --upgradable читає локальний кеш і не лізе в мережу.
        local upgradable
        upgradable=$(apt list --upgradable 2>/dev/null | grep -c "upgradable from" || true)
        if (( upgradable == 0 )); then
            result PASS "Пакети для оновлення" "0 (за кешем apt)"
        elif (( upgradable > 20 )); then
            result FAIL "Пакети для оновлення" "$upgradable — систему давно не оновлювали"
        else
            result WARN "Пакети для оновлення" "$upgradable"
        fi

        if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
            result PASS "Автоматичні оновлення безпеки" "unattended-upgrades налаштовано"
        else
            result WARN "Автоматичні оновлення безпеки" "unattended-upgrades не налаштовано"
        fi
    elif have dnf; then
        result SKIP "Пакети для оновлення" "перевірте: dnf check-update"
    else
        result SKIP "Пакети для оновлення" "невідомий пакетний менеджер"
    fi
}
check_updates

# ============================================================================
# 5. ЗАХИСТ ДАНИХ
# ============================================================================
section "5. Захист даних"

check_encryption() {
    if [[ "$OS" == "macos" ]]; then
        if have fdesetup; then
            if fdesetup status 2>/dev/null | grep -qi "FileVault is On"; then
                result PASS "Шифрування диска (FileVault)" "увімкнено"
            else
                result FAIL "Шифрування диска (FileVault)" "вимкнено"
            fi
        else
            result SKIP "Шифрування диска" "fdesetup недоступний"
        fi
        return
    fi

    if [[ "$OS" == "wsl" ]]; then
        result SKIP "Шифрування диска" "у WSL за це відповідає BitLocker на боці Windows"
        return
    fi

    if have lsblk; then
        if lsblk -o TYPE 2>/dev/null | grep -q crypt; then
            result PASS "Шифрування диска (LUKS)" "знайдено зашифрований том"
        else
            result WARN "Шифрування диска (LUKS)" "зашифрованих томів не видно"
        fi
    else
        result SKIP "Шифрування диска" "lsblk недоступний"
    fi
}
check_encryption

# Обов'язковий контроль доступу: AppArmor (Ubuntu/SUSE) або SELinux (RHEL).
check_mac() {
    if [[ "$OS" == "macos" ]]; then
        if have spctl; then
            if spctl --status 2>/dev/null | grep -qi "assessments enabled"; then
                result PASS "Gatekeeper" "увімкнено"
            else
                result FAIL "Gatekeeper" "вимкнено — запуститься будь-який непідписаний бінарник"
            fi
        fi
        if have csrutil; then
            if csrutil status 2>/dev/null | grep -qi "enabled"; then
                result PASS "System Integrity Protection" "увімкнено"
            else
                result FAIL "System Integrity Protection" "вимкнено"
            fi
        fi
        return
    fi

    if have aa-status; then
        if aa-status --enabled 2>/dev/null; then
            result PASS "AppArmor" "увімкнено"
        else
            result WARN "AppArmor" "вимкнено"
        fi
    elif have getenforce; then
        local mode
        mode=$(getenforce 2>/dev/null || echo "?")
        case "$mode" in
            Enforcing)  result PASS "SELinux" "Enforcing" ;;
            Permissive) result WARN "SELinux" "Permissive — лише логує, не блокує" ;;
            *)          result FAIL "SELinux" "$mode" ;;
        esac
    else
        result SKIP "AppArmor / SELinux" "не встановлено"
    fi
}
check_mac

# ============================================================================
# 6. ОБЛІКОВІ ЗАПИСИ
# ============================================================================
section "6. Облікові записи"

check_accounts() {
    if [[ ! -r /etc/passwd ]]; then
        result SKIP "Облікові записи з UID 0" "/etc/passwd недоступний"
        return
    fi

    # UID 0 = права root. Другий такий запис — або помилка адміністрування,
    # або бекдор, який залишив атакувальник.
    local root_users
    root_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | tr '\n' ' ')
    #  -F: — поля розділені двокрапкою; $1 = ім'я, $3 = UID.

    if [[ "$(echo "$root_users" | wc -w)" -eq 1 ]]; then
        result PASS "Облікові записи з UID 0" "лише root"
    else
        result FAIL "Облікові записи з UID 0" "$root_users"
    fi

    # Порожні паролі. /etc/shadow читається лише під root — тому SKIP,
    # а не «все добре».
    if [[ -r /etc/shadow ]]; then
        local empty
        empty=$(awk -F: '($2 == "") {print $1}' /etc/shadow | tr '\n' ' ')
        if [[ -z "$empty" ]]; then
            result PASS "Порожні паролі" "не знайдено"
        else
            result FAIL "Порожні паролі" "$empty"
        fi
    else
        result SKIP "Порожні паролі" "/etc/shadow потребує sudo"
    fi
}
[[ "$OS" == "macos" ]] || check_accounts

# Файли з правами 777 у домашньому каталозі: типовий наслідок
# «а давай просто chmod 777, щоб запрацювало».
check_perms() {
    local count
    count=$(find "$HOME" -maxdepth 3 -type f -perm -o+w ! -type l 2>/dev/null | wc -l | tr -d ' ')
    #  -perm -o+w  — «біт запису для інших встановлено»
    #  ! -type l   — не рахувати символьні посилання
    #  2>/dev/null — сховати скарги на каталоги без прав доступу
    if (( count == 0 )); then
        result PASS "Файли, доступні на запис усім" "0 у ~ (глибина 3)"
    else
        result WARN "Файли, доступні на запис усім" "$count у ~ (глибина 3)"
    fi
}
check_perms

# Права на приватні ключі SSH. Має бути 600: тільки власник.
check_ssh_keys() {
    local key perms bad=0 total=0
    [[ -d "$HOME/.ssh" ]] || { result SKIP "Права на ключі SSH" "каталог .ssh відсутній"; return; }

    for key in "$HOME"/.ssh/id_*; do
        [[ -f "$key" ]] || continue
        [[ "$key" == *.pub ]] && continue      # публічні ключі можуть бути 644
        total=$((total + 1))

        # stat має різний синтаксис у GNU та BSD — класична пастка
        # кросплатформенного скрипта.
        if [[ "$OS" == "macos" ]]; then
            perms=$(stat -f "%Lp" "$key" 2>/dev/null || echo "?")
        else
            perms=$(stat -c "%a" "$key" 2>/dev/null || echo "?")
        fi

        [[ "$perms" == "600" || "$perms" == "400" ]] || bad=$((bad + 1))
    done

    if (( total == 0 )); then
        result SKIP "Права на ключі SSH" "приватних ключів не знайдено"
    elif (( bad == 0 )); then
        result PASS "Права на ключі SSH" "$total ключ(ів), усі 600/400"
    else
        result FAIL "Права на ключі SSH" "$bad з $total мають зайві права"
    fi
}
check_ssh_keys

# ============================================================================
# 7. СЕКРЕТИ В ОТОЧЕННІ
# ============================================================================
section "7. Секрети"

check_secrets() {
    # Історія shell — місце, де реально знаходять паролі й токени.
    local hist="${HISTFILE:-$HOME/.bash_history}"
    [[ -r "$hist" ]] || hist="$HOME/.zsh_history"

    if [[ -r "$hist" ]]; then
        local hits
        hits=$(grep -icE '(password|passwd|token|api[_-]?key|secret)=[^ ]{6,}' "$hist" 2>/dev/null || true)
        if (( hits == 0 )); then
            result PASS "Секрети в історії команд" "збігів немає"
        else
            result WARN "Секрети в історії команд" "$hits підозрілих рядків у $(basename "$hist")"
        fi
    else
        result SKIP "Секрети в історії команд" "файл історії не знайдено"
    fi

    # .env поруч із кодом — окрема класика. Шукаємо лише те, що ще й
    # доступне на читання іншим користувачам системи.
    local envs
    envs=$(find "$HOME" -maxdepth 4 -name ".env" -type f -perm -o+r 2>/dev/null | wc -l | tr -d ' ')
    if (( envs == 0 )); then
        result PASS "Файли .env, читані всіма" "0"
    else
        result WARN "Файли .env, читані всіма" "$envs — поставте chmod 600"
    fi
}
check_secrets

# ============================================================================
# ПІДСУМОК
# ============================================================================

total=$((pass_count + fail_count + warn_count + skip_count))

printf '\n%s\n' "${BOLD}──────────────── Підсумок ────────────────${RESET}"
printf '  %sPASS%s %-3s  %sFAIL%s %-3s  %sWARN%s %-3s  %sSKIP%s %-3s   разом: %s\n' \
    "$GREEN" "$RESET" "$pass_count" \
    "$RED"   "$RESET" "$fail_count" \
    "$YELLOW" "$RESET" "$warn_count" \
    "$DIM"   "$RESET" "$skip_count" "$total"

if (( fail_count > 0 )); then
    printf '\n%sЄ критичні знахідки — розберіть кожен FAIL.%s\n' "$RED$BOLD" "$RESET"
elif (( warn_count > 0 )); then
    printf '\n%sКритичного немає, але перегляньте WARN.%s\n' "$YELLOW" "$RESET"
else
    printf '\n%sБазові перевірки пройдено.%s\n' "$GREEN" "$RESET"
fi

if (( skip_count > 0 )); then
    printf '%s%d перевірок пропущено — частину видно лише під sudo.%s\n' "$DIM" "$skip_count" "$RESET"
fi

printf '\n%sДля повного аудиту:%s sudo lynis audit system\n' "$DIM" "$RESET"

# Код повернення для CI: 1, якщо є хоч один FAIL.
(( fail_count == 0 ))
