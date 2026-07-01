#!/bin/bash

# ============================================================================
# СКРИПТ АНАЛИЗА ЗАЩИЩЕННОСТИ ASTRA LINUX SE 1.7/1.8
# Версия: 2.3
# Описание: Сбор параметров безопасности и сравнение с эталонными значениями
# ============================================================================

# Файл для сохранения результатов
OUTPUT_FILE="security_report_full_$(date +%Y%m%d_%H%M%S).txt"

# Цветовое оформление для экрана
HEADER_COLOR="\033[1;34m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
NC="\033[0m" # No Color

# ============================================================================
# БАЗА ЭТАЛОННЫХ ЗНАЧЕНИЙ
# ============================================================================

declare -A EXPECTED_VALUES=(
    # Парольная политика (Раздел 1)
    ["PASS_MAX_DAYS"]="90"
    ["PASS_MIN_DAYS"]="7"
    ["PASS_WARN_AGE"]="14"
    ["deny"]="8"
    ["per_user"]="включен"
    ["dcredit"]="1"
    ["difok"]="3"
    ["lcredit"]="1"
    ["minlen"]="12"
    ["ocredit"]="1"
    ["ucredit"]="1"
    ["reject_username"]="да"
    ["gecoscheck"]="да"
    ["enforce_for_root_complex"]="да"
    ["enforce_for_root_history"]="да"
    ["remember"]="5"
    ["inactive_shadow"]="90"
    ["INACTIVE"]="90"
    
    # Инструменты командной строки Astra (Раздел 2)
    ["astra-sudo-control"]="ВКЛЮЧЕНО"
    ["astra-shutdown-lock"]="ВКЛЮЧЕНО"
    ["astra-mount-lock"]="ВКЛЮЧЕНО"
    ["astra-format-lock"]="ВКЛЮЧЕНО"
    ["astra-mic-control"]="АКТИВНО"
    ["astra-strictmode-control"]="ВЫКЛЮЧЕНО"
    ["astra-ufw-control"]="ВЫКЛЮЧЕНО"
    ["astra-nochmodx-lock"]="ВКЛЮЧЕНО"
    ["astra-ptrace-lock"]="ВЫКЛЮЧЕНО"
    ["astra-ulimits-control"]="ВЫКЛЮЧЕНО"
    ["astra-lkrg-control"]="ВЫКЛЮЧЕНО"
    ["astra-rootloginssh-control"]="ВКЛЮЧЕНО"
    ["astra-docker-isolation"]="ВКЛЮЧЕНО"
    ["astra-ilev1-control"]="ВКЛЮЧЕНО"
    ["astra-audit-control"]="ENABLE"
    ["astra-audit-network-control"]="ENABLE"
    ["astra-modban-lock"]="ENABLE"
    ["astra-noautonet-control"]="ВКЛЮЧЕНО"
    ["astra-hardened-control"]="ВЫКЛЮЧЕНО"
    ["astra-console-lock"]="ВКЛЮЧЕНО"
    ["astra-interpreters-lock"]="ВКЛЮЧЕНО"
    ["astra-bash-lock"]="ВЫКЛЮЧЕНО"
    ["astra-digsig-control"]="ВЫКЛЮЧЕНО"
    ["astra-secdel-control"]="ВКЛЮЧЕНО"
    ["astra-swapwiper-control"]="ВКЛЮЧЕНО"
    
    # Параметры ядра (Раздел 3)
    ["net.ipv4.ip_forward"]="выключено"
    ["net.ipv4.conf.all.accept_redirects"]="выключено"
    ["net.ipv4.conf.all.secure_redirects"]="выключено"
    ["net.ipv4.conf.all.send_redirects"]="выключено"
    ["fs.protected_hardlinks"]="включено"
    ["fs.protected_symlinks"]="включено"
    ["fs.suid_dumpable"]="включено"
    ["kernel.randomize_va_space"]="включено"
    ["net.ipv4.conf.default.rp_filter"]="включено"
    ["net.ipv4.conf.all.rp_filter"]="включено"
    ["kernel.dmesg_restrict"]="включено"
    ["kernel.yama.ptrace_scope"]="включено"
    ["kernel.perf_event_paranoid"]="включено"
    ["vm.unprivileged_userfaultfd"]="включено"
    
    # Конфигурация SSH (Раздел 4)
    ["PermitRootLogin"]="no"
    ["MaxAuthTries"]="3"
    ["MaxSessions"]="10"
    ["StrictModes"]="yes"
    ["PubkeyAuthentication"]="yes"
)

# ============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================================

# Функция сравнения значений
compare_value() {
    local current_value="$1"
    local expected_value="$2"
    local comparison_type="$3"

    if [[ -z "$current_value" ]] || [[ "$current_value" == "не задан" ]] || [[ "$current_value" == "не установлен" ]] || [[ "$current_value" == "файл отсутствует" ]]; then
        echo "НЕ СООТВЕТСТВУЕТ"
        return
    fi

    local current_lower=$(echo "$current_value" | tr '[:upper:]' '[:lower:]')
    local expected_lower=$(echo "$expected_value" | tr '[:upper:]' '[:lower:]')

    case "$comparison_type" in
        "eq")
            if [[ "$current_lower" == "$expected_lower" ]]; then
                echo "СООТВЕТСТВУЕТ"
            else
                echo "НЕ СООТВЕТСТВУЕТ"
            fi
            ;;
        "ge")
            if [[ "$current_value" =~ ^[0-9]+$ ]] && [[ "$expected_value" =~ ^[0-9]+$ ]]; then
                if [[ "$current_value" -ge "$expected_value" ]]; then
                    echo "СООТВЕТСТВУЕТ"
                else
                    echo "НЕ СООТВЕТСТВУЕТ"
                fi
            else
                echo "НЕИЗВЕСТНЫЙ ТИП"
            fi
            ;;
        "le")
            if [[ "$current_value" =~ ^[0-9]+$ ]] && [[ "$expected_value" =~ ^[0-9]+$ ]]; then
                if [[ "$current_value" -le "$expected_value" ]]; then
                    echo "СООТВЕТСТВУЕТ"
                else
                    echo "НЕ СООТВЕТСТВУЕТ"
                fi
            else
                echo "НЕИЗВЕСТНЫЙ ТИП"
            fi
            ;;
        *)
            echo "НЕИЗВЕСТНЫЙ ТИП"
            ;;
    esac
}

# Функция для получения значения PAM
get_pam_value() {
    local param=$1
    local value=$(grep -E "pam_(cracklib|pwquality)\.so" /etc/pam.d/common-password 2>/dev/null | grep -oP "$param=\K\d+" | head -1)
    if [[ -n "$value" ]]; then
        echo "$value"
    else
        echo "не задан"
    fi
}

# Функция для проверки флага PAM
check_pam_flag() {
    local flag=$1
    local file=$2
    if grep -E "pam_(cracklib|pwquality)\.so" "$file" 2>/dev/null | grep -q "$flag"; then
        echo "да"
    else
        echo "не задан"
    fi
}

# Функция для получения параметра аутентификации
get_auth_param() {
    local param=$1
    local value=$(grep -E "pam_tally2\.so|pam_faillock\.so" /etc/pam.d/common-auth 2>/dev/null | grep -oP "$param=\K\d+" | head -1)
    if [[ -n "$value" ]]; then
        echo "$value"
    else
        echo "не задан"
    fi
}

# Функция для проверки статуса astra-* утилит
check_astra_tool() {
    local tool=$1
    if command -v "$tool" &>/dev/null; then
        local status=$($tool 2>/dev/null | grep -i "статус\|status\|включ\|выключ\|enabled\|disabled" | head -1)
        if [[ -n "$status" ]]; then
            if echo "$status" | grep -qi "включ\|enabled\|active\|активно"; then
                if [[ "$tool" == "astra-mic-control" ]]; then
                    echo "АКТИВНО"
                else
                    echo "ВКЛЮЧЕНО"
                fi
            elif echo "$status" | grep -qi "выключ\|disabled\|inactive"; then
                echo "ВЫКЛЮЧЕНО"
            else
                echo "$status"
            fi
        else
            echo "установлен"
        fi
    else
        echo "не установлен"
    fi
}

# Функция для проверки параметров ядра
check_kernel_param() {
    local param=$1
    local value=$(sysctl -n "$param" 2>/dev/null)
    if [[ -n "$value" ]]; then
        case $value in
            0) echo "выключено" ;;
            1) echo "включено" ;;
            2) echo "включено" ;;
            *) echo "$value" ;;
        esac
    else
        echo "не задан"
    fi
}

# ============================================================================
# ФУНКЦИИ ДЛЯ ВЫВОДА ОТЧЕТА С ВЫРАВНИВАНИЕМ ЧЕРЕЗ ПРОБЕЛЫ
# ============================================================================

# Функция для получения статуса с цветом
get_status_colored() {
    local status="$1"
    case "$status" in
        "СООТВЕТСТВУЕТ") echo "${GREEN}СООТВЕТСТВУЕТ${NC}" ;;
        "НЕ СООТВЕТСТВУЕТ") echo "${RED}НЕ СООТВЕТСТВУЕТ${NC}" ;;
        *) echo "${YELLOW}НЕ ПРОВЕРЕНО${NC}" ;;
    esac
}

# Функция для вывода строки таблицы (раздел 1 - парольная политика)
print_row() {
    local name="$1"
    local file="$2"
    local param="$3"
    local current_value="$4"
    local expected_value="$5"
    local comparison_type="$6"
    local status=$(compare_value "$current_value" "$expected_value" "$comparison_type")

    # Запись в файл (без цветов)
    echo "$name|$file|$param|$current_value|$expected_value|$status" >> "$OUTPUT_FILE"

    # Вывод на экран (с цветами)
    local status_colored=$(get_status_colored "$status")
    printf "${HEADER_COLOR}%-70s${NC} %-30s %-30s %-20s %-20s %s\n" \
        "$name" "$file" "$param" "$current_value" "$expected_value" "$status_colored"
}

# Функция для вывода строки инструментов Astra (раздел 2)
print_tool_row() {
    local name="$1"
    local param="$2"
    local current_value="$3"
    local expected_value="${EXPECTED_VALUES[$param]}"
    
    if [[ -z "$expected_value" ]]; then
        expected_value="не задан"
        local status="НЕ ПРОВЕРЕНО"
    else
        local status=$(compare_value "$current_value" "$expected_value" "eq")
    fi

    # Запись в файл (без цветов)
    echo "$name|$param|$current_value|$expected_value|$status" >> "$OUTPUT_FILE"

    # Вывод на экран (с цветами)
    local status_colored=$(get_status_colored "$status")
    printf "${HEADER_COLOR}%-90s${NC} %-35s %-20s %-20s %s\n" \
        "$name" "$param" "$current_value" "$expected_value" "$status_colored"
}

# Функция для вывода строки параметров ядра (раздел 3)
print_kernel_row() {
    local name="$1"
    local param="$2"
    local current_value="$3"
    local expected_value="${EXPECTED_VALUES[$param]}"
    
    if [[ -z "$expected_value" ]]; then
        expected_value="не задан"
        local status="НЕ ПРОВЕРЕНО"
    else
        local status=$(compare_value "$current_value" "$expected_value" "eq")
    fi

    # Запись в файл (без цветов)
    echo "$name|$param|$current_value|$expected_value|$status" >> "$OUTPUT_FILE"

    # Вывод на экран (с цветами)
    local status_colored=$(get_status_colored "$status")
    printf "${HEADER_COLOR}%-80s${NC} %-60s %-20s %-20s %s\n" \
        "$name" "$param" "$current_value" "$expected_value" "$status_colored"
}

# Функция для вывода строки SSH (раздел 4)
print_ssh_row() {
    local name="$1"
    local param="$2"
    local current_value="$3"
    local expected_value="${EXPECTED_VALUES[$param]}"
    
    if [[ -z "$expected_value" ]]; then
        expected_value="не задан"
        local status="НЕ ПРОВЕРЕНО"
    else
        local status=$(compare_value "$current_value" "$expected_value" "eq")
    fi

    # Запись в файл (без цветов)
    echo "$name|$param|$current_value|$expected_value|$status" >> "$OUTPUT_FILE"

    # Вывод на экран (с цветами)
    local status_colored=$(get_status_colored "$status")
    printf "${HEADER_COLOR}%-45s${NC} %-25s %-20s %-20s %s\n" \
        "$name" "$param" "$current_value" "$expected_value" "$status_colored"
}

# ============================================================================
# ЗАГОЛОВОК ОТЧЕТА
# ============================================================================

clear
> "$OUTPUT_FILE"

echo "================================================================================" | tee -a "$OUTPUT_FILE"
echo "  СКРИПТ АНАЛИЗА ЗАЩИЩЕННОСТИ ASTRA LINUX SE 1.7/1.8" | tee -a "$OUTPUT_FILE"
echo "  Дата: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# ============================================================================
# РАЗДЕЛ 1: ПАРОЛЬНАЯ ПОЛИТИКА
# ============================================================================
echo "" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"
echo "  РАЗДЕЛ 1: ПАРОЛЬНАЯ ПОЛИТИКА" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"

HEADER_ROW1="Наименование настройки                                                Расположение файла             Наименование параметра           Текущее значение    Требуемое значение  Статус"
echo "$HEADER_ROW1" >> "$OUTPUT_FILE"
echo "------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> "$OUTPUT_FILE"
echo -e "${HEADER_COLOR}${HEADER_ROW1}${NC}"
echo -e "${HEADER_COLOR}------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------${NC}"

# 1. PASS_MAX_DAYS
value=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
[[ -z "$value" ]] && value="не задан"
print_row "Максимальное количество дней использования пароля                     " "/etc/login.defs                " "PASS_MAX_DAYS                    " "$value" "90" "le"

# 2. PASS_MIN_DAYS
value=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
[[ -z "$value" ]] && value="не задан"
print_row "Минимальное количество дней между сменами пароля                      " "/etc/login.defs                " "PASS_MIN_DAYS                    " "$value" "7" "ge"

# 3. PASS_WARN_AGE
value=$(grep "^PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}')
[[ -z "$value" ]] && value="не задан"
print_row "Количество дней предупреждения до истечения срока действия пароля     " "/etc/login.defs                " "PASS_WARN_AGE                    " "$value" "14" "ge"

# 4. deny
value=$(get_auth_param "deny")
print_row "Количество неудачных попыток входа до блокировки аккаунта             " "/etc/pam.d/common-auth         " "deny                             " "$value" "8" "eq"

# 5. per_user
if grep -E "pam_tally2\.so|pam_faillock\.so" /etc/pam.d/common-auth 2>/dev/null | grep -q "per_user"; then
    value="включен"
else
    value="не задан"
fi
print_row "Отдельная статистика неудачных попыток для каждого пользователя       " "/etc/pam.d/common-auth         " "per_user                         " "$value" "включен" "eq"

# 6. dcredit
value=$(get_pam_value "dcredit")
print_row "Требования к цифрам                                                   " "/etc/pam.d/common-password     " "dcredit                          " "$value" "1" "eq"

# 7. difok
value=$(get_pam_value "difok")
print_row "Минимальное количество символов, отличающихся от старого пароля       " "/etc/pam.d/common-password     " "difok                            " "$value" "3" "eq"

# 8. lcredit
value=$(get_pam_value "lcredit")
print_row "Требования к строчным буквам                                          " "/etc/pam.d/common-password     " "lcredit                          " "$value" "1" "eq"

# 9. minlen
value=$(get_pam_value "minlen")
print_row "Минимальная длина пароля в символах                                   " "/etc/pam.d/common-password     " "minlen                           " "$value" "12" "ge"

# 10. ocredit
value=$(get_pam_value "ocredit")
print_row "Требования к специальным символам                                     " "/etc/pam.d/common-password     " "ocredit                          " "$value" "1" "eq"

# 11. ucredit
value=$(get_pam_value "ucredit")
print_row "Требования к заглавным буквам                                         " "/etc/pam.d/common-password     " "ucredit                          " "$value" "1" "eq"

# 12. reject_username
if grep -E "pam_(cracklib|pwquality)\.so" /etc/pam.d/common-password 2>/dev/null | grep -q "reject_username"; then
    value="да"
else
    value="не задан"
fi
print_row "Пароль не должен содержать имя пользователя                           " "/etc/pam.d/common-password     " "reject_username                  " "$value" "да" "eq"

# 13. gecoscheck
if grep -E "pam_(cracklib|pwquality)\.so" /etc/pam.d/common-password 2>/dev/null | grep -q "gecoscheck"; then
    value="да"
else
    value="не задан"
fi
print_row "Пароль не должен содержать данные из поля GECOS                       " "/etc/pam.d/common-password     " "gecoscheck                       " "$value" "да" "eq"

# 14. enforce_for_root (сложность)
value=$(check_pam_flag "enforce_for_root" "/etc/pam.d/common-password")
print_row "Требования к сложности пароля применяются и к root                    " "/etc/pam.d/common-password     " "enforce_for_root (сложность)     " "$value" "да" "eq"

# 15. enforce_for_root (история)
if grep "pam_unix.so" /etc/pam.d/common-password 2>/dev/null | grep -q "enforce_for_root"; then
    value="да"
else
    value="не задан"
fi
print_row "Требования к истории пароля применяются и к root                      " "/etc/pam.d/common-password     " "enforce_for_root (история)       " "$value" "да" "eq"

# 16. remember
value=$(grep "pam_unix.so" /etc/pam.d/common-password 2>/dev/null | grep -oP 'remember=\K\d+' | head -1)
[[ -z "$value" ]] && value="не задан"
print_row "Количество паролей, которые нужно запомнить                           " "/etc/pam.d/common-password     " "remember                         " "$value" "5" "ge"

# 17. INACTIVE из /etc/default/useradd
if [ -f /etc/default/useradd ]; then
    value=$(grep "^INACTIVE" /etc/default/useradd 2>/dev/null | cut -d= -f2)
    [[ -z "$value" ]] && value="не задан"
else
    value="файл отсутствует"
fi
print_row "Количество дней неактивности до отключения учётной записи             " "/etc/default/useradd           " "INACTIVE                         " "$value" "90" "eq"

# ============================================================================
# РАЗДЕЛ 2: ИНСТРУМЕНТЫ КОМАНДНОЙ СТРОКИ ASTRA LINUX
# ============================================================================
echo "" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"
echo "  РАЗДЕЛ 2: ИНСТРУМЕНТЫ КОМАНДНОЙ СТРОКИ ASTRA LINUX" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"

HEADER_TOOL="Наименование настройки                                                                                                      Действия/параметр              Текущее значение    Требуемое значение  Статус"
echo "$HEADER_TOOL" >> "$OUTPUT_FILE"
echo "------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> "$OUTPUT_FILE"
echo -e "${HEADER_COLOR}${HEADER_TOOL}${NC}"
echo -e "${HEADER_COLOR}------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------${NC}"

print_tool_row "Запрос пароля при каждом выполнении команды sudo                                                                            " "astra-sudo-control             " "$(check_astra_tool "astra-sudo-control")"
print_tool_row "Управление блокировкой выключения/перезагрузки ПК для пользователей                                                         " "astra-shutdown-lock           " "$(check_astra_tool "astra-shutdown-lock")"
print_tool_row "Включение режима запрета монтирования носителей непривилегированным пользователям                                           " "astra-mount-lock              " "$(check_astra_tool "astra-mount-lock")"
print_tool_row "Включение режима запрета форматирования съемных машинных носителей информации непривилегированным пользователям             " "astra-format-lock             " "$(check_astra_tool "astra-format-lock")"
print_tool_row "Мандатный контроль целостности                                                                                             " "astra-mic-control             " "$(check_astra_tool "astra-mic-control")"
print_tool_row "Расширенный режим мандатного контроля целостности                                                                          " "astra-strictmode-control      " "$(check_astra_tool "astra-strictmode-control")"
print_tool_row "Межсетевой экран ufw                                                                                                       " "astra-ufw-control             " "$(check_astra_tool "astra-ufw-control")"
print_tool_row "Запрет установки бита исполнения                                                                                           " "astra-nochmodx-lock           " "$(check_astra_tool "astra-nochmodx-lock")"
print_tool_row "Блокировка трассировки ptrace для всех пользователей, включая администраторов                                              " "astra-ptrace-lock             " "$(check_astra_tool "astra-ptrace-lock")"
print_tool_row "Установка системных ограничений ulimits                                                                                    " "astra-ulimits-control         " "$(check_astra_tool "astra-ulimits-control")"
print_tool_row "Загрузка модуля ядра lkrg                                                                                                  " "astra-lkrg-control            " "$(check_astra_tool "astra-lkrg-control")"
print_tool_row "Ограничение доступа root по SSH                                                                                            " "astra-rootloginssh-control    " "$(check_astra_tool "astra-rootloginssh-control")"
print_tool_row "Запуск контейнеров Docker на пониженном уровне МКЦ                                                                         " "astra-docker-isolation        " "$(check_astra_tool "astra-docker-isolation")"
print_tool_row "Запуск сетевых сервисов на пониженном уровне МКЦ                                                                           " "astra-ilev1-control           " "$(check_astra_tool "astra-ilev1-control")"
print_tool_row "Правила PARSEC-аудита процессов и файлов                                                                                   " "astra-audit-control           " "$(check_astra_tool "astra-audit-control")"
print_tool_row "Правила сетевого PARSEC-аудита                                                                                             " "astra-audit-network-control   " "$(check_astra_tool "astra-audit-network-control")"
print_tool_row "Блокировка неиспользуемых модулей ядра                                                                                     " "astra-modban-lock             " "$(check_astra_tool "astra-modban-lock")"
print_tool_row "Блокировка автоматического конфигурирования сетевых подключений                                                            " "astra-noautonet-control       " "$(check_astra_tool "astra-noautonet-control")"
print_tool_row "Управление блокировкой загрузкой ядра hardened (в загрузчике GRUB 2)                                                       " "astra-hardened-control        " "$(check_astra_tool "astra-hardened-control")"
print_tool_row "Блокировка консоли для пользователей, не входящих в группу astra-console                                                   " "astra-console-lock            " "$(check_astra_tool "astra-console-lock")"
print_tool_row "Блокировка интерпретаторов (кроме bash)                                                                                    " "astra-interpreters-lock       " "$(check_astra_tool "astra-interpreters-lock")"
print_tool_row "Блокировка интерпретатора Bash                                                                                             " "astra-bash-lock               " "$(check_astra_tool "astra-bash-lock")"
print_tool_row "Механизм контроля целостности исполняемых файлов и разделяемых библиотек формата ELF при запуске программы на выполнение   " "astra-digsig-control          " "$(check_astra_tool "astra-digsig-control")"
print_tool_row "Механизм очистки памяти                                                                                                    " "astra-secdel-control          " "$(check_astra_tool "astra-secdel-control")"
print_tool_row "Механизм очистки разделов подкачки                                                                                         " "astra-swapwiper-control       " "$(check_astra_tool "astra-swapwiper-control")"

# ============================================================================
# РАЗДЕЛ 3: ПАРАМЕТРЫ БЕЗОПАСНОСТИ ЯДРА
# ============================================================================
echo "" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"
echo "  РАЗДЕЛ 3: ПАРАМЕТРЫ БЕЗОПАСНОСТИ ЯДРА" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"

HEADER_KERNEL="Наименование настройки                                                                  Конфигурируемый параметр                                                                                    Текущее значение    Требуемое значение  Статус"
echo "$HEADER_KERNEL" >> "$OUTPUT_FILE"
echo "------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> "$OUTPUT_FILE"
echo -e "${HEADER_COLOR}${HEADER_KERNEL}${NC}"
echo -e "${HEADER_COLOR}------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------${NC}"

print_kernel_row "Отключение переадресации IP пакетов (IP forwarding)                                                                     " "net.ipv4.ip_forward                                                                               " "$(check_kernel_param "net.ipv4.ip_forward")"
print_kernel_row "Параметры, отвечающие за выдачу ICMP Redirect (ICMP перенаправления) другим хостам                                      " "net.ipv4.conf.all.accept_redirects, net.ipv4.conf.all.secure_redirects, net.ipv4.conf.all.send_redirects    " "$(check_kernel_param "net.ipv4.conf.all.accept_redirects") $(check_kernel_param "net.ipv4.conf.all.secure_redirects") $(check_kernel_param "net.ipv4.conf.all.send_redirects")"
print_kernel_row "Ограничение небезопасных вариантов работы с жесткими ссылками (hardlinks)                                              " "fs.protected_hardlinks                                                                            " "$(check_kernel_param "fs.protected_hardlinks")"
print_kernel_row "Ограничение небезопасных вариантов прохода по символическим ссылкам (symlinks)                                         " "fs.protected_symlinks                                                                             " "$(check_kernel_param "fs.protected_symlinks")"
print_kernel_row "Запрет создания core dump для некоторых исполняемых файлов                                                              " "fs.suid_dumpable                                                                                  " "$(check_kernel_param "fs.suid_dumpable")"
print_kernel_row "Рандомизация адресного пространства, которая защищает от атак на переполнение буфера                                    " "kernel.randomize_va_space                                                                         " "$(check_kernel_param "kernel.randomize_va_space")"
print_kernel_row "Использование фильтрации обратного пути по умолчанию (для новых интерфейсов)                                            " "net.ipv4.conf.default.rp_filter                                                                   " "$(check_kernel_param "net.ipv4.conf.default.rp_filter")"
print_kernel_row "Использование фильтрации обратного пути у всех интерфейсов                                                              " "net.ipv4.conf.all.rp_filter                                                                       " "$(check_kernel_param "net.ipv4.conf.all.rp_filter")"
print_kernel_row "Ограничение доступа к журналу ядра                                                                                      " "kernel.dmesg_restrict                                                                             " "$(check_kernel_param "kernel.dmesg_restrict")"
print_kernel_row "Запрет подключения к другим процессам с помощью ptrace                                                                  " "kernel.yama.ptrace_scope                                                                          " "$(check_kernel_param "kernel.yama.ptrace_scope")"
print_kernel_row "Ограничение доступа к событиям производительности                                                                       " "kernel.perf_event_paranoid                                                                        " "$(check_kernel_param "kernel.perf_event_paranoid")"
print_kernel_row "Запрет системного вызова userfaultfd для непривилегированных пользователей                                               " "vm.unprivileged_userfaultfd                                                                       " "$(check_kernel_param "vm.unprivileged_userfaultfd")"

# ============================================================================
# РАЗДЕЛ 4: КОНФИГУРАЦИЯ SSH СЕРВЕРА
# ============================================================================
echo "" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"
echo "  РАЗДЕЛ 4: КОНФИГУРАЦИЯ SSH СЕРВЕРА" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"

HEADER_SSH="Наименование настройки                                  Параметр                Текущее значение    Требуемое значение  Статус"
echo "$HEADER_SSH" >> "$OUTPUT_FILE"
echo "------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> "$OUTPUT_FILE"
echo -e "${HEADER_COLOR}${HEADER_SSH}${NC}"
echo -e "${HEADER_COLOR}------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------${NC}"

if [ -f /etc/ssh/sshd_config ]; then
    port=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$port" ]] && port="22"
    print_ssh_row "Порт, на котором слушает SSH сервер                     " "Port                   " "$port"

    permit_root=$(grep -E "^PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$permit_root" ]] && permit_root="prohibit-password"
    print_ssh_row "Разрешение входа пользователю root по SSH               " "PermitRootLogin        " "$permit_root"

    strict_modes=$(grep -E "^StrictModes " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$strict_modes" ]] && strict_modes="yes"
    print_ssh_row "Проверка прав и владельцев файлов/каталогов             " "StrictModes            " "$strict_modes"

    max_auth_tries=$(grep -E "^MaxAuthTries " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$max_auth_tries" ]] && max_auth_tries="6"
    print_ssh_row "Максимальное число попыток аутентификации               " "MaxAuthTries           " "$max_auth_tries"

    max_sessions=$(grep -E "^MaxSessions " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$max_sessions" ]] && max_sessions="10"
    print_ssh_row "Максимальное число сессий на соединение                 " "MaxSessions            " "$max_sessions"

    pubkey_auth=$(grep -E "^PubkeyAuthentication " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$pubkey_auth" ]] && pubkey_auth="yes"
    print_ssh_row "Аутентификация по открытому ключу (публичным ключам)    " "PubkeyAuthentication   " "$pubkey_auth"
else
    echo "SSH сервер не установлен или конфиг не найден" | tee -a "$OUTPUT_FILE"
fi

# Проверка fail2ban
if command -v fail2ban-client &>/dev/null; then
    fail2ban_status="установлен"
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        fail2ban_status="установлен и активен"
    fi
else
    fail2ban_status="не установлен"
fi
print_ssh_row "Наличие ПО fail2ban                                    " "fail2ban               " "$fail2ban_status"

# ============================================================================
# РАЗДЕЛ 5: ИНФОРМАЦИЯ ОБ УЧЁТНЫХ ЗАПИСЯХ
# ============================================================================
echo "" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"
echo "  РАЗДЕЛ 5: ИНФОРМАЦИЯ ОБ УЧЁТНЫХ ЗАПИСЯХ ПОЛЬЗОВАТЕЛЕЙ" | tee -a "$OUTPUT_FILE"
echo "  (ДОЛЖНА БЫТЬ ПРИМЕНЕНА КО ВСЕМ УЗ, КРОМЕ iacaudit. root должна быть выключена)" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"

HEADER_ACCOUNTS="Наименование учетной записи    Парольная информация    Количество дней после последнего изменения пароля    Минимальное количество дней до смены пароля     Количество дней действия пароля    Число дней выдачи предупреждения до смены пароля     Число дней неактивности после устаревания пароля до блокировки учетной записи    Срок действия учетной записи пользователя"
echo "$HEADER_ACCOUNTS" >> "$OUTPUT_FILE"
echo "--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> "$OUTPUT_FILE"
echo -e "${HEADER_COLOR}${HEADER_ACCOUNTS}${NC}"
echo -e "${HEADER_COLOR}--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------${NC}"

# Функция для получения информации об учётной записи
get_account_info() {
    local username="$1"

    if ! id "$username" &>/dev/null; then
        return
    fi

    local shadow_line=$(sudo grep "^$username:" /etc/shadow 2>/dev/null)

    if [[ -z "$shadow_line" ]]; then
        printf "%-27s %-22s %-55s %-45s %-32s %-51s %-76s %-43s\n" \
            "$username" "нет пароля" "-" "-" "-" "-" "-" "-" >> "$OUTPUT_FILE"
        printf "${HEADER_COLOR}%-27s${NC} %-22s %-55s %-45s %-32s %-51s %-76s %-43s\n" \
            "$username" "нет пароля" "-" "-" "-" "-" "-" "-"
        return
    fi

    IFS=':' read -r user pass last_change min_days max_days warn_days inactive expire rest <<< "$shadow_line"

    if [[ "$pass" == "*" || "$pass" == "!" || "$pass" == "!!" ]]; then
        password_info="Заблокирован"
    elif [[ "$pass" =~ ^\$6\$ ]]; then
        password_info="зашифрован"
    elif [[ -z "$pass" ]]; then
        password_info="нет пароля"
    else
        password_info="установлен"
    fi

    if [[ "$last_change" =~ ^[0-9]+$ ]] && [[ "$last_change" -gt 0 ]]; then
        local current_epoch=$(date +%s)
        local current_days=$((current_epoch / 86400))
        local days_since_change=$((current_days - last_change))
        last_change="$days_since_change"
    else
        last_change="-"
    fi

    [[ ! "$min_days" =~ ^[0-9]+$ ]] && min_days="-"
    [[ "$max_days" =~ ^[0-9]+$ ]] && [[ "$max_days" -eq 99999 ]] && max_days="-"
    [[ ! "$warn_days" =~ ^[0-9]+$ ]] && warn_days="-"
    [[ ! "$inactive" =~ ^[0-9]+$ ]] && inactive="-"

    if [[ "$expire" =~ ^[0-9]+$ ]] && [[ "$expire" -gt 0 ]]; then
        expire=$(date -d "1970-01-01 + $expire days" +"%Y-%m-%d" 2>/dev/null)
        [[ -z "$expire" ]] && expire="-"
    else
        expire="-"
    fi

    printf "%-27s %-22s %-55s %-45s %-32s %-51s %-76s %-43s\n" \
        "$username" "$password_info" "$last_change" "$min_days" "$max_days" "$warn_days" "$inactive" "$expire" >> "$OUTPUT_FILE"

    printf "${HEADER_COLOR}%-27s${NC} %-22s %-55s %-45s %-32s %-51s %-76s %-43s\n" \
        "$username" "$password_info" "$last_change" "$min_days" "$max_days" "$warn_days" "$inactive" "$expire"
}

# Получаем информацию об учётных записях
get_account_info "root"

while IFS=: read -r username _ uid _ _ _ _; do
    if [[ $uid -ge 1000 ]] && [[ $uid -lt 65534 ]] 2>/dev/null; then
        get_account_info "$username"
    fi
done < /etc/passwd

# ============================================================================
# ЗАВЕРШЕНИЕ
# ============================================================================
echo "" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"

# Подсчет статистики
total_checks=$(grep -c "|" "$OUTPUT_FILE" 2>/dev/null || echo 0)
failed_checks=$(grep -c "НЕ СООТВЕТСТВУЕТ" "$OUTPUT_FILE" 2>/dev/null || echo 0)
passed_checks=$(grep -c "СООТВЕТСТВУЕТ" "$OUTPUT_FILE" 2>/dev/null || echo 0)

echo "📊 СТАТИСТИКА ПРОВЕРКИ:" | tee -a "$OUTPUT_FILE"
echo "   ✅ Соответствует: $passed_checks" | tee -a "$OUTPUT_FILE"
echo "   ❌ Не соответствует: $failed_checks" | tee -a "$OUTPUT_FILE"
echo "   📝 Всего проверок: $total_checks" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

echo "✅ Полный отчет сохранен в файл: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
echo "📁 Полный путь: $(pwd)/$OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"
