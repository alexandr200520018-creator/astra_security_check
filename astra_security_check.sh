#!/bin/bash

# Файл для сохранения результатов
OUTPUT_FILE="security_report_full_$(date +%Y%m%d_%H%M%S).txt"

# Цветовое оформление для экрана
HEADER_COLOR="\033[1;34m"
NC="\033[0m"

# Функция для вывода строки таблицы (без цветов, для файла)
print_row_to_file() {
    local name="$1"
    local file="$2"
    local param="$3"
    local value="$4"

    echo "$name$file$param$value" >> "$OUTPUT_FILE"
}

# Функция для вывода строки таблицы на экран (с цветами)
print_row_to_screen() {
    local name="$1"
    local file="$2"
    local param="$3"
    local value="$4"

    echo -e "${HEADER_COLOR}${name}${NC}${file}${param}${value}"
}

# Функции для получения значений
get_pam_value() {
    local param=$1
    local value=$(grep -E "pam_(cracklib|pwquality)\.so" /etc/pam.d/common-password 2>/dev/null | grep -oP "$param=\K\d+" | head -1)
    if [[ -n "$value" ]]; then
        echo "$value"
    else
        echo "не задан"
    fi
}

check_pam_flag() {
    local flag=$1
    local file=$2
    if grep -E "pam_(cracklib|pwquality)\.so" "$file" 2>/dev/null | grep -q "$flag"; then
        echo "да"
    else
        echo "не задан"
    fi
}

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
            echo "$status"
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

# Очищаем файл перед записью
> "$OUTPUT_FILE"

# Функция для одновременного вывода
print_row() {
    local name="$1"
    local file="$2"
    local param="$3"
    local value="$4"

    print_row_to_screen "$name" "$file" "$param" "$value"
    print_row_to_file "$name" "$file" "$param" "$value"
}

# ============================================================================
# РАЗДЕЛ 1: ПАРОЛЬНАЯ ПОЛИТИКА
# ============================================================================
echo "" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"
echo "  РАЗДЕЛ 1: ПАРОЛЬНАЯ ПОЛИТИКА" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"

# Заголовок
HEADER_ROW="Наименование настройки                                                Расположение файла             Наименование параметра           Значение"
echo "$HEADER_ROW" >> "$OUTPUT_FILE"
echo "--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> "$OUTPUT_FILE"
echo -e "${HEADER_COLOR}${HEADER_ROW}${NC}"
echo -e "${HEADER_COLOR}--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------${NC}"

# 1. Максимальное количество дней использования пароля
value=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
[[ -z "$value" ]] && value="не задан"
print_row "Максимальное количество дней использования пароля                     " "/etc/login.defs                " "PASS_MAX_DAYS                    " "$value"

# 2. Минимальное количество дней между сменами пароля
value=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
[[ -z "$value" ]] && value="не задан"
print_row "Минимальное количество дней между сменами пароля                      " "/etc/login.defs                " "PASS_MIN_DAYS                    " "$value"

# 3. Количество дней предупреждения до истечения срока
value=$(grep "^PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}')
[[ -z "$value" ]] && value="не задан"
print_row "Количество дней предупреждения до истечения срока действия пароля     " "/etc/login.defs                " "PASS_WARN_AGE                    " "$value"

# 4. Количество неудачных попыток входа до блокировки
value=$(get_auth_param "deny")
print_row "Количество неудачных попыток входа до блокировки аккаунта             " "/etc/pam.d/common-auth         " "deny                             " "$value"

# 5. Отдельная статистика для каждого пользователя
if grep -E "pam_tally2\.so|pam_faillock\.so" /etc/pam.d/common-auth 2>/dev/null | grep -q "per_user"; then
    value="включен"
else
    value="не задан"
fi
print_row "Отдельная статистика неудачных попыток для каждого пользователя       " "/etc/pam.d/common-auth         " "per_user                         " "$value"

# 6. Требования к цифрам
value=$(get_pam_value "dcredit")
print_row "Требования к цифрам                                                   " "/etc/pam.d/common-password     " "dcredit                          " "$value"

# 7. Минимальное количество символов, отличающихся от старого пароля
value=$(get_pam_value "difok")
print_row "Минимальное количество символов, отличающихся от старого пароля       " "/etc/pam.d/common-password     " "difok                            " "$value"

# 8. Требования к строчным буквам
value=$(get_pam_value "lcredit")
print_row "Требования к строчным буквам                                          " "/etc/pam.d/common-password     " "lcredit                          " "$value"

# 9. Минимальная длина пароля
value=$(get_pam_value "minlen")
print_row "Минимальная длина пароля в символах                                   " "/etc/pam.d/common-password     " "minlen                           " "$value"

# 10. Требования к специальным символам
value=$(get_pam_value "ocredit")
print_row "Требования к специальным символам                                     " "/etc/pam.d/common-password     " "ocredit                          " "$value"

# 11. Требования к заглавным буквам
value=$(get_pam_value "ucredit")
print_row "Требования к заглавным буквам                                         " "/etc/pam.d/common-password     " "ucredit                          " "$value"

# 12. Время блокировки
value=$(get_auth_param "lock_time")
print_row "Время блокировки в секундах                                           " "/etc/pam.d/common-auth         " "lock_time                        " "$value"

# 13. Не использовать счетчик для root
if grep -E "pam_tally2\.so|pam_faillock\.so" /etc/pam.d/common-auth 2>/dev/null | grep -q "magic_root"; then
    value="включен"
else
    value="не задан"
fi
print_row "Не использовать счетчик для пользователя с uid=0 (root)               " "/etc/pam.d/common-auth         " "magic_root                       " "$value"

# 14. Время разблокировки
value=$(get_auth_param "unlock_time")
print_row "Время разблокировки в секундах                                        " "/etc/pam.d/common-auth         " "unlock_time                      " "$value"

# 15. Дней неактивности до отключения аккаунта
value=$(sudo awk -F: -v user=$(whoami) '$1==user {print $7}' /etc/shadow 2>/dev/null)
if [[ -z "$value" || "$value" == "" || "$value" == "99999" ]]; then
    value="не задан"
fi
print_row "Дней неактивности до автоматического отключения аккаунта              " "/etc/shadow                     " "inactive                         " "$value"

# 16. Пароль не должен содержать имя пользователя
if grep -E "pam_(cracklib|pwquality)\.so" /etc/pam.d/common-password 2>/dev/null | grep -q "reject_username"; then
    value="да"
else
    value="не задан"
fi
print_row "Пароль не должен содержать имя пользователя                           " "/etc/pam.d/common-password     " "reject_username                  " "$value"

# 17. Пароль не должен содержать данные из GECOS
if grep -E "pam_(cracklib|pwquality)\.so" /etc/pam.d/common-password 2>/dev/null | grep -q "gecoscheck"; then
    value="да"
else
    value="не задан"
fi
print_row "Пароль не должен содержать данные из поля GECOS                       " "/etc/pam.d/common-password     " "gecoscheck                       " "$value"

# 18. enforce_for_root (сложность)
value=$(check_pam_flag "enforce_for_root" "/etc/pam.d/common-password")
print_row "Требования к сложности пароля применяются и к root                    " "/etc/pam.d/common-password     " "enforce_for_root (сложность)     " "$value"

# 19. enforce_for_root для истории
if grep "pam_unix.so" /etc/pam.d/common-password 2>/dev/null | grep -q "enforce_for_root"; then
    value="да"
else
    value="не задан"
fi
print_row "Требования к истории пароля применяются и к root                      " "/etc/pam.d/common-password     " "enforce_for_root (история)       " "$value"

# 20. remember
value=$(grep "pam_unix.so" /etc/pam.d/common-password 2>/dev/null | grep -oP 'remember=\K\d+' | head -1)
print_row "Количество паролей, которые нужно запомнить                           " "/etc/pam.d/common-password     " "remember                         " "${value:-не задан}"

# 21. INACTIVE из /etc/default/useradd
if [ -f /etc/default/useradd ]; then
    value=$(grep "^INACTIVE" /etc/default/useradd 2>/dev/null | cut -d= -f2)
    [[ -z "$value" ]] && value="не задан"
else
    value="файл отсутствует"
fi
print_row "Количество дней неактивности до отключения учётной записи             " "/etc/default/useradd           " "INACTIVE                         " "$value"

# 22. EXPIRE из /etc/default/useradd
if [ -f /etc/default/useradd ]; then
    value=$(grep "^EXPIRE" /etc/default/useradd 2>/dev/null | cut -d= -f2)
    [[ -z "$value" ]] && value="не задан"
else
    value="файл отсутствует"
fi
print_row "Дата истечения срока действия учётной записи по умолчанию             " "/etc/default/useradd           " "EXPIRE                           " "$value"

# ============================================================================
# РАЗДЕЛ 2: ИНСТРУМЕНТЫ КОМАНДНОЙ СТРОКИ ASTRA LINUX
# ============================================================================
echo "" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"
echo "  РАЗДЕЛ 2: ИНСТРУМЕНТЫ КОМАНДНОЙ СТРОКИ ASTRA LINUX" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"

HEADER_TOOL="Наименование настройки                                                                                                      Действия/параметр              Значение"
echo "$HEADER_TOOL" >> "$OUTPUT_FILE"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------------" >> "$OUTPUT_FILE"
echo -e "${HEADER_COLOR}${HEADER_TOOL}${NC}"
echo -e "${HEADER_COLOR}----------------------------------------------------------------------------------------------------------------------------------------------------------------${NC}"

print_tool_row() {
    local name="$1"
    local param="$2"
    local value="$3"
    local line="${name}${param}${value}"
    echo "$line" >> "$OUTPUT_FILE"
    echo -e "${HEADER_COLOR}${name}${NC}${param}${value}"
}

print_tool_row "Запрос пароля при каждом выполнении команды sudo                                                                            " "astra-sudo-control             " "$(check_astra_tool "astra-sudo-control")"
print_tool_row "Управление блокировкой выключения/перезагрузки ПК для пользователей                                                         " "astra-shutdown-lock           " "$(check_astra_tool "astra-shutdown-lock")"
print_tool_row "Включение режима запрета монтирования носителей непривилегированным пользователям                                           " "astra-mount-lock              " "$(check_astra_tool "astra-mount-lock")"

format_lock_status=$(check_astra_tool "fly-admin-format")
print_tool_row "Включение режима запрета форматирования съемных машинных носителей информации непривилегированным пользователям             " "astra-format-lock             " "$format_lock_status"

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

HEADER_KERNEL="Наименование настройки                                                                  Конфигурируемый параметр                                                                                    Статус"
echo "$HEADER_KERNEL" >> "$OUTPUT_FILE"
echo "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> "$OUTPUT_FILE"
echo -e "${HEADER_COLOR}${HEADER_KERNEL}${NC}"
echo -e "${HEADER_COLOR}-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------${NC}"

print_kernel_row() {
    local name="$1"
    local param="$2"
    local status="$3"
    local line="${name}${param}${status}"
    echo "$line" >> "$OUTPUT_FILE"
    echo -e "${HEADER_COLOR}${name}${NC}${param}${status}"
}

# Параметры ядра
print_kernel_row "Отключение переадресации IP пакетов (IP forwarding)                                                                     " "net.ipv4.ip_forward                                                                               " "$(check_kernel_param "net.ipv4.ip_forward")"

accept_redirects=$(check_kernel_param "net.ipv4.conf.all.accept_redirects")
secure_redirects=$(check_kernel_param "net.ipv4.conf.all.secure_redirects")
send_redirects=$(check_kernel_param "net.ipv4.conf.all.send_redirects")
icmp_status="accept_redirects: $accept_redirects; secure_redirects: $secure_redirects; send_redirects: $send_redirects"
print_kernel_row "Параметры, отвечающие за выдачу ICMP Redirect (ICMP перенаправления) другим хостам                                      " "net.ipv4.conf.all.accept_redirects, net.ipv4.conf.all.secure_redirects, net.ipv4.conf.all.send_redirects    " "$icmp_status"

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

HEADER_SSH="Наименование настройки                                  Параметр                Значение"
echo "$HEADER_SSH" >> "$OUTPUT_FILE"
echo "-----------------------------------------------------------------------------------------------------------------" >> "$OUTPUT_FILE"
echo -e "${HEADER_COLOR}${HEADER_SSH}${NC}"
echo -e "${HEADER_COLOR}-----------------------------------------------------------------------------------------------------------------${NC}"

print_ssh_row() {
    local name="$1"
    local param="$2"
    local value="$3"
    local line="${name}${param}${value}"
    echo "$line" >> "$OUTPUT_FILE"
    echo -e "${HEADER_COLOR}${name}${NC}${param}${value}"
}

if [ -f /etc/ssh/sshd_config ]; then
    port=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$port" ]] && port="22"

    listen_addr=$(grep -E "^ListenAddress " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tr '\n' ', ' | sed 's/, $//')
    [[ -z "$listen_addr" ]] && listen_addr="0.0.0.0"

    login_grace=$(grep -E "^LoginGraceTime " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$login_grace" ]] && login_grace="120"

    permit_root=$(grep -E "^PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$permit_root" ]] && permit_root="prohibit-password"
    [[ "$permit_root" == "yes" ]] && permit_root="YES"
    [[ "$permit_root" == "no" ]] && permit_root="NO"

    strict_modes=$(grep -E "^StrictModes " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$strict_modes" ]] && strict_modes="yes"

    max_auth_tries=$(grep -E "^MaxAuthTries " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$max_auth_tries" ]] && max_auth_tries="6"

    max_sessions=$(grep -E "^MaxSessions " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$max_sessions" ]] && max_sessions="10"

    pubkey_auth=$(grep -E "^PubkeyAuthentication " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$pubkey_auth" ]] && pubkey_auth="yes"

    print_ssh_row "Порт, на котором слушает SSH сервер                     " "Port                   " "$port"
    print_ssh_row "Адрес(а), на которых слушает SSH сервер                 " "ListenAddress          " "$listen_addr"
    print_ssh_row "Время ожидания входа до разрыва соединения              " "LoginGraceTime         " "$login_grace"
    print_ssh_row "Разрешение входа пользователю root по SSH               " "PermitRootLogin        " "$permit_root"
    print_ssh_row "Проверка прав и владельцев файлов/каталогов             " "StrictModes            " "$strict_modes"
    print_ssh_row "Максимальное число попыток аутентификации               " "MaxAuthTries           " "$max_auth_tries"
    print_ssh_row "Максимальное число сессий на соединение                 " "MaxSessions            " "$max_sessions"
    print_ssh_row "Аутентификация по открытому ключу (публичным ключам)    " "PubkeyAuthentication   " "$pubkey_auth"
else
    print_ssh_row "SSH сервер не установлен или конфиг не найден           " "-                      " "-"
fi

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
# РАЗДЕЛ 5: ИНФОРМАЦИЯ ОБ УЧЁТНЫХ ЗАПИСЯХ ПОЛЬЗОВАТЕЛЕЙ
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

    # Проверяем существует ли пользователь
    if ! id "$username" &>/dev/null; then
        return
    fi

    # Получаем информацию из /etc/shadow
    local shadow_line=$(sudo grep "^$username:" /etc/shadow 2>/dev/null)

    if [[ -z "$shadow_line" ]]; then
        # Пользователь есть в /etc/passwd, но нет в /etc/shadow (пароль не установлен)
        printf "%-27s %-22s %-55s %-45s %-32s %-51s %-76s %-43s\n" \
            "$username" "нет пароля" "-" "-" "-" "-" "-" "-" >> "$OUTPUT_FILE"
        printf "${HEADER_COLOR}%-27s${NC} %-22s %-55s %-45s %-32s %-51s %-76s %-43s\n" \
            "$username" "нет пароля" "-" "-" "-" "-" "-" "-"
        return
    fi

    # Разбираем поля /etc/shadow
    # Формат: username:password:last_change:min_days:max_days:warn_days:inactive:expire:reserved
    IFS=':' read -r user pass last_change min_days max_days warn_days inactive expire rest <<< "$shadow_line"

    # Определяем парольную информацию
    if [[ "$pass" == "*" || "$pass" == "!" || "$pass" == "!!" ]]; then
        password_info="Заблокирован"
    elif [[ "$pass" =~ ^\$6\$ ]]; then
        password_info="зашифрован"
    elif [[ -z "$pass" ]]; then
        password_info="нет пароля"
    else
        password_info="установлен"
    fi

    # Преобразуем last_change в дни после последнего изменения
    if [[ "$last_change" =~ ^[0-9]+$ ]] && [[ "$last_change" -gt 0 ]]; then
        local current_epoch=$(date +%s)
        local current_days=$((current_epoch / 86400))
        local days_since_change=$((current_days - last_change))
        last_change="$days_since_change"
    else
        last_change="-"
    fi

    # Обработка остальных полей
    if [[ "$min_days" =~ ^[0-9]+$ ]]; then
        [[ "$min_days" -eq 0 ]] && min_days="0"
    else
        min_days="-"
    fi

    if [[ "$max_days" =~ ^[0-9]+$ ]]; then
        [[ "$max_days" -eq 99999 ]] && max_days="-"
    else
        max_days="-"
    fi

    if [[ ! "$warn_days" =~ ^[0-9]+$ ]]; then
        warn_days="-"
    fi

    if [[ ! "$inactive" =~ ^[0-9]+$ ]]; then
        inactive="-"
    fi

    # Преобразуем expire в дату
    if [[ "$expire" =~ ^[0-9]+$ ]] && [[ "$expire" -gt 0 ]]; then
        expire=$(date -d "1970-01-01 + $expire days" +"%Y-%m-%d" 2>/dev/null)
        [[ -z "$expire" ]] && expire="-"
    else
        expire="-"
    fi

    # Формируем строку с фиксированной шириной
    # Ширина столбцов: 27, 22, 55, 45, 32, 51, 76, 43
    printf "%-27s %-22s %-55s %-45s %-32s %-51s %-76s %-43s\n" \
        "$username" \
        "$password_info" \
        "$last_change" \
        "$min_days" \
        "$max_days" \
        "$warn_days" \
        "$inactive" \
        "$expire" >> "$OUTPUT_FILE"

    printf "${HEADER_COLOR}%-27s${NC} %-22s %-55s %-45s %-32s %-51s %-76s %-43s\n" \
        "$username" \
        "$password_info" \
        "$last_change" \
        "$min_days" \
        "$max_days" \
        "$warn_days" \
        "$inactive" \
        "$expire"
}

# Получаем информацию об учётных записях
# Сначала root
get_account_info "root"

# Затем всех пользователей с UID >= 1000 и UID < 65534 (исключая системных)
while IFS=: read -r username _ uid _ _ _ _; do
    if [[ $uid -ge 1000 ]] && [[ $uid -lt 65534 ]] 2>/dev/null; then
        get_account_info "$username"
    fi
done < /etc/passwd

echo "" | tee -a "$OUTPUT_FILE"
# ============================================================================
# ЗАВЕРШЕНИЕ
# ============================================================================
echo "" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"
echo "✅ Полный отчет сохранен в файл: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
echo "📁 Полный путь: $(pwd)/$OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
echo "================================================================================" | tee -a "$OUTPUT_FILE"
