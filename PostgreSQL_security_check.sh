#!/bin/bash

# ============================================================
# НАСТРОЙКИ ПРОГРАММЫ
# ============================================================

# Параметры подключения к PostgreSQL
PG_USER="postgres"
PG_HOST="localhost"
PG_PORT="5432"

# Файл для сохранения отчёта
OUTPUT_MD="pg_audit_report_$(date +%Y%m%d_%H%M%S).md"
OUTPUT_TXT="pg_audit_report_$(date +%Y%m%d_%H%M%S).txt"

# Цвета для вывода на экран
HEADER_COLOR="\033[1;34m"
GREEN_COLOR="\033[0;32m"
RED_COLOR="\033[0;31m"
YELLOW_COLOR="\033[1;33m"
NC="\033[0m"

# ============================================================
# ФУНКЦИИ ДЛЯ РАБОТЫ С POSTGRESQL
# ============================================================

# Выполнение SQL-запроса и возврат результата
execute_sql() {
    local query="$1"
    PGPASSWORD="$PG_PASSWORD" psql -U "$PG_USER" -h "$PG_HOST" -p "$PG_PORT" -d postgres -t -A -c "$query" 2>/dev/null
}

# Получение значения параметра PostgreSQL
get_pg_setting() {
    local param="$1"
    local value=$(execute_sql "SHOW $param;")
    if [[ -z "$value" ]]; then
        echo "не задан"
    else
        echo "$value"
    fi
}

# Проверка включено ли расширение
check_extension() {
    local ext_name="$1"
    local value=$(execute_sql "SELECT COUNT(*) FROM pg_extension WHERE extname = '$ext_name';")
    if [[ "$value" -eq 1 ]]; then
        echo "включено"
    else
        echo "отключено"
    fi
}

# Проверка наличия файла и его прав
check_file_permissions() {
    local file_path="$1"
    local required_perms="$2"
    local owner="$3"
    
    if [[ ! -f "$file_path" ]]; then
        echo "файл не найден"
        return
    fi
    
    local perms=$(stat -c "%a" "$file_path" 2>/dev/null)
    local file_owner=$(stat -c "%U" "$file_path" 2>/dev/null)
    
    if [[ "$perms" == "$required_perms" ]] && [[ "$file_owner" == "$owner" ]]; then
        echo "OK ($perms, $file_owner)"
    else
        echo "НЕ СООТВЕТСТВУЕТ (текущие: $perms, $file_owner; требуется: $required_perms, $owner)"
    fi
}

# ============================================================
# ФУНКЦИЯ АУДИТА
# ============================================================

TOTAL_PASS=0
TOTAL_FAIL=0

audit_parameter() {
    local name="$1"
    local current_value="$2"
    local required_value="$3"
    local comment="$4"
    local status=""
    local md_status=""
    
    if [[ "$current_value" == "$required_value" ]]; then
        status="СООТВЕТСТВУЕТ"
        md_status="Соответствует"
        ((TOTAL_PASS++))
        [[ -z "$comment" ]] && comment="Параметр настроен верно."
    elif [[ "$current_value" == "не задан" || "$current_value" == "отключено" ]]; then
        status="НЕ СООТВЕТСТВУЕТ"
        md_status="Не соответствует"
        ((TOTAL_FAIL++))
        [[ -z "$comment" ]] && comment="Параметр не задан или отключён."
    elif [[ "$current_value" == *"НЕ СООТВЕТСТВУЕТ"* ]]; then
        status="НЕ СООТВЕТСТВУЕТ"
        md_status="Не соответствует"
        ((TOTAL_FAIL++))
        [[ -z "$comment" ]] && comment="$current_value"
        current_value="не соответствует"
    else
        status="НЕ СООТВЕТСТВУЕТ"
        md_status="Не соответствует"
        ((TOTAL_FAIL++))
        [[ -z "$comment" ]] && comment="Текущее значение отличается от требуемого."
    fi
    
    # Вывод в консоль (с цветами)
    local status_color=""
    case "$status" in
        "СООТВЕТСТВУЕТ") status_color="${GREEN_COLOR}" ;;
        "НЕ СООТВЕТСТВУЕТ") status_color="${RED_COLOR}" ;;
        *) status_color="${YELLOW_COLOR}" ;;
    esac
    
    printf "${HEADER_COLOR}%-50s${NC} | ${YELLOW_COLOR}%-25s${NC} | ${GREEN_COLOR}%-25s${NC} | ${status_color}%-30s${NC} | ${NC}%-60s\n" \
           "$name" "$current_value" "$required_value" "$status" "$comment"
    
    # Запись в TXT (без цветов)
    printf "%-50s | %-25s | %-25s | %-30s | %-60s\n" \
           "$name" "$current_value" "$required_value" "$status" "$comment" >> "$OUTPUT_TXT"
    
    # Запись в MD
    printf "| %-50s | %-25s | %-25s | %-30s | %-60s |\n" \
           "$name" "$current_value" "$required_value" "$md_status" "$comment" >> "$OUTPUT_MD"
}

# ============================================================
# НАЧАЛО ВЫПОЛНЕНИЯ
# ============================================================

clear
echo -e "${HEADER_COLOR}🔐 Аудит безопасности PostgreSQL${NC}"
echo "========================================================================"
echo -n "Введите пароль пользователя $PG_USER: "
read -s PG_PASSWORD
echo ""
echo ""

# Проверка подключения
if ! PGPASSWORD="$PG_PASSWORD" psql -U "$PG_USER" -h "$PG_HOST" -p "$PG_PORT" -d postgres -c "SELECT 1;" &>/dev/null; then
    echo -e "${RED_COLOR}❌ Ошибка: Не удалось подключиться к PostgreSQL.${NC}"
    echo "Проверьте:"
    echo "  - Запущен ли сервер PostgreSQL"
    echo "  - Правильность пароля"
    echo "  - Доступность хоста $PG_HOST и порта $PG_PORT"
    exit 1
fi

echo -e "${GREEN_COLOR}✅ Успешное подключение к PostgreSQL${NC}"
echo ""

# Инициализация файлов отчёта
> "$OUTPUT_MD"
> "$OUTPUT_TXT"

# Получаем версию PostgreSQL
PG_VERSION=$(PGPASSWORD="$PG_PASSWORD" psql -U "$PG_USER" -h "$PG_HOST" -p "$PG_PORT" -d postgres -t -c "SELECT version();" 2>/dev/null | head -1 | xargs)

# Заголовок отчёта в MD
cat > "$OUTPUT_MD" << EOF
# Отчёт по аудиту безопасности PostgreSQL

**Дата проверки:** $(date '+%Y-%m-%d %H:%M:%S')
**Сервер:** $PG_HOST:$PG_PORT
**Пользователь:** $PG_USER
**Версия PostgreSQL:** $PG_VERSION

---

## 1. Аутентификация и управление доступом

| Наименование параметра | Текущее значение | Требуемое значение | Статус проверки | Комментарий |
|---|---|---|---|---|
EOF

# Заголовок отчёта в TXT
cat > "$OUTPUT_TXT" << EOF
================================================================================
  Отчёт по аудиту безопасности PostgreSQL
================================================================================
Дата проверки: $(date '+%Y-%m-%d %H:%M:%S')
Сервер: $PG_HOST:$PG_PORT
Пользователь: $PG_USER
Версия PostgreSQL: $PG_VERSION

================================================================================
  1. АУТЕНТИФИКАЦИЯ И УПРАВЛЕНИЕ ДОСТУПОМ
================================================================================
Наименование параметра                                  | Текущее значение           | Требуемое значение           | Статус проверки                 | Комментарий
--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|
EOF

# Заголовок в консоли
echo ""
echo "================================================================================"
echo -e "${HEADER_COLOR}  АУДИТ АУТЕНТИФИКАЦИИ И УПРАВЛЕНИЯ ДОСТУПОМ${NC}"
echo "================================================================================"
printf "${HEADER_COLOR}%-50s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-30s${NC} | ${HEADER_COLOR}%-60s${NC}\n" \
       "Наименование параметра" "Текущее значение" "Требуемое значение" "Статус проверки" "Комментарий"
echo "--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|"

# ---------- 1. Шифрование паролей ----------
current=$(get_pg_setting "password_encryption")
audit_parameter "Шифрование паролей" "$current" "scram-sha-256" ""

# ---------- 2. Модуль проверки сложности пароля ----------
current=$(get_pg_setting "passwordcheck")
audit_parameter "Модуль проверки сложности пароля" "$current" "on" ""

# ---------- 3. Проверка pg_hba.conf на метод trust ----------
trust_lines=$(PGPASSWORD="$PG_PASSWORD" psql -U "$PG_USER" -h "$PG_HOST" -p "$PG_PORT" -d postgres -t -A -c "SELECT COUNT(*) FROM pg_hba_file_rules WHERE auth_method = 'trust';" 2>/dev/null)
if [[ "$trust_lines" -gt 0 ]]; then
    current="обнаружен метод trust ($trust_lines записей)"
else
    current="не обнаружен"
fi
audit_parameter "Использование метода trust в pg_hba.conf" "$current" "не обнаружен" "Метод trust опасен — используется аутентификация без пароля"

# ---------- 4. Проверка защиты схемы public ----------
public_priv=$(PGPASSWORD="$PG_PASSWORD" psql -U "$PG_USER" -h "$PG_HOST" -p "$PG_PORT" -d postgres -t -A -c "SELECT COUNT(*) FROM pg_namespace n JOIN pg_roles r ON n.nspowner = r.oid WHERE n.nspname = 'public' AND r.rolname = 'postgres';" 2>/dev/null)
if [[ "$public_priv" -eq 1 ]]; then
    current="защищена (владелец postgres)"
else
    current="не защищена"
fi
audit_parameter "Защита схемы public" "$current" "защищена" "Рекомендуется: REVOKE CREATE ON SCHEMA public FROM PUBLIC;"

# ---------- 5. Проверка суперпользователей ----------
superusers=$(PGPASSWORD="$PG_PASSWORD" psql -U "$PG_USER" -h "$PG_HOST" -p "$PG_PORT" -d postgres -t -A -c "SELECT COUNT(*) FROM pg_authid WHERE rolsuper = true;" 2>/dev/null)
if [[ "$superusers" -eq 1 ]]; then
    current="1 ($PG_USER)"
else
    current="$superusers пользователей"
fi
audit_parameter "Количество суперпользователей" "$current" "1 (только $PG_USER)" ""

# ============================================================
# РАЗДЕЛ 2: ЖУРНАЛИРОВАНИЕ И АУДИТ
# ============================================================

echo "" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "  2. ЖУРНАЛИРОВАНИЕ И АУДИТ" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "Наименование параметра                                  | Текущее значение           | Требуемое значение           | Статус проверки                 | Комментарий" >> "$OUTPUT_TXT"
echo "--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|" >> "$OUTPUT_TXT"

cat >> "$OUTPUT_MD" << EOF

---

## 2. Журналирование и аудит

| Наименование параметра | Текущее значение | Требуемое значение | Статус проверки | Комментарий |
|---|---|---|---|---|
EOF

echo ""
echo "================================================================================"
echo -e "${HEADER_COLOR}  АУДИТ ЖУРНАЛИРОВАНИЯ И АУДИТА${NC}"
echo "================================================================================"
printf "${HEADER_COLOR}%-50s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-30s${NC} | ${HEADER_COLOR}%-60s${NC}\n" \
       "Наименование параметра" "Текущее значение" "Требуемое значение" "Статус проверки" "Комментарий"
echo "--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|"

# ---------- 6. pgAudit ----------
current=$(check_extension "pgaudit")
audit_parameter "Расширение pgAudit" "$current" "включено" ""

# ---------- 7. log_connections ----------
current=$(get_pg_setting "log_connections")
audit_parameter "Логирование подключений" "$current" "on" ""

# ---------- 8. log_disconnections ----------
current=$(get_pg_setting "log_disconnections")
audit_parameter "Логирование отключений" "$current" "on" ""

# ---------- 9. log_line_prefix ----------
current=$(get_pg_setting "log_line_prefix")
required='%m [%p] %q%u@%d'
audit_parameter "Формат строки логирования" "$current" "$required" "Должен содержать %m (время), %u (пользователь), %d (БД)"

# ---------- 10. log_statement ----------
current=$(get_pg_setting "log_statement")
audit_parameter "Логирование SQL-запросов" "$current" "ddl" ""

# ---------- 11. log_rotation_age ----------
current=$(get_pg_setting "log_rotation_age")
audit_parameter "Период ротации логов" "$current" "1d" ""

# ---------- 12. log_rotation_size ----------
current=$(get_pg_setting "log_rotation_size")
audit_parameter "Максимальный размер лога" "$current" "10MB" ""

# ============================================================
# РАЗДЕЛ 3: СЕТЕВЫЕ НАСТРОЙКИ И ШИФРОВАНИЕ
# ============================================================

echo "" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "  3. СЕТЕВЫЕ НАСТРОЙКИ И ШИФРОВАНИЕ" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "Наименование параметра                                  | Текущее значение           | Требуемое значение           | Статус проверки                 | Комментарий" >> "$OUTPUT_TXT"
echo "--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|" >> "$OUTPUT_TXT"

cat >> "$OUTPUT_MD" << EOF

---

## 3. Сетевые настройки и шифрование

| Наименование параметра | Текущее значение | Требуемое значение | Статус проверки | Комментарий |
|---|---|---|---|---|
EOF

echo ""
echo "================================================================================"
echo -e "${HEADER_COLOR}  АУДИТ СЕТЕВЫХ НАСТРОЕК И ШИФРОВАНИЯ${NC}"
echo "================================================================================"
printf "${HEADER_COLOR}%-50s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-30s${NC} | ${HEADER_COLOR}%-60s${NC}\n" \
       "Наименование параметра" "Текущее значение" "Требуемое значение" "Статус проверки" "Комментарий"
echo "--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|"

# ---------- 13. SSL включён ----------
current=$(get_pg_setting "ssl")
audit_parameter "Использование SSL" "$current" "on" ""

# ---------- 14. ssl_ciphers ----------
current=$(get_pg_setting "ssl_ciphers")
required="HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4"
audit_parameter "SSL-шифры" "$current" "$required" "Рекомендуются только надёжные шифры"

# ---------- 15. listen_addresses ----------
current=$(get_pg_setting "listen_addresses")
audit_parameter "Адреса для прослушивания" "$current" "'*' или '0.0.0.0'" "Проверьте, что только необходимые адреса открыты"

# ============================================================
# РАЗДЕЛ 4: БЕЗОПАСНОСТЬ НА УРОВНЕ ФАЙЛОВОЙ СИСТЕМЫ
# ============================================================

echo "" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "  4. БЕЗОПАСНОСТЬ НА УРОВНЕ ФАЙЛОВОЙ СИСТЕМЫ" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "Наименование параметра                                  | Текущее значение           | Требуемое значение           | Статус проверки                 | Комментарий" >> "$OUTPUT_TXT"
echo "--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|" >> "$OUTPUT_TXT"

cat >> "$OUTPUT_MD" << EOF

---

## 4. Безопасность на уровне файловой системы

| Наименование параметра | Текущее значение | Требуемое значение | Статус проверки | Комментарий |
|---|---|---|---|---|
EOF

echo ""
echo "================================================================================"
echo -e "${HEADER_COLOR}  АУДИТ БЕЗОПАСНОСТИ НА УРОВНЕ ФАЙЛОВОЙ СИСТЕМЫ${NC}"
echo "================================================================================"
printf "${HEADER_COLOR}%-50s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-30s${NC} | ${HEADER_COLOR}%-60s${NC}\n" \
       "Наименование параметра" "Текущее значение" "Требуемое значение" "Статус проверки" "Комментарий"
echo "--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|"

# ---------- 16. Права на PGDATA ----------
pgdata=$(PGPASSWORD="$PG_PASSWORD" psql -U "$PG_USER" -h "$PG_HOST" -p "$PG_PORT" -d postgres -t -A -c "SHOW data_directory;" 2>/dev/null)
if [[ -n "$pgdata" ]]; then
    current=$(check_file_permissions "$pgdata" "700" "postgres")
else
    current="не определено"
fi
audit_parameter "Права на директорию PGDATA" "$current" "OK (700, postgres)" ""

# ---------- 17. Контрольные суммы данных ----------
current=$(get_pg_setting "data_checksums")
audit_parameter "Контрольные суммы данных" "$current" "on" "Включить при инициализации кластера: initdb --data-checksums"

# ============================================================
# ЗАВЕРШЕНИЕ
# ============================================================

cat >> "$OUTPUT_MD" << EOF

---

## 5. Сводка по результатам аудита

| Статус | Количество |
|--------|------------|
| ✅ Соответствует | $TOTAL_PASS |
| ❌ Не соответствует | $TOTAL_FAIL |
| 📊 Всего проверено | $(($TOTAL_PASS + $TOTAL_FAIL)) |
EOF

echo "" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "  5. СТАТИСТИКА АУДИТА" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "✅ Соответствует: $TOTAL_PASS" >> "$OUTPUT_TXT"
echo "❌ Не соответствует: $TOTAL_FAIL" >> "$OUTPUT_TXT"
echo "📊 Всего проверено: $(($TOTAL_PASS + $TOTAL_FAIL))" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"

echo ""
echo "================================================================================"
echo -e "${HEADER_COLOR}  СТАТИСТИКА АУДИТА${NC}"
echo "================================================================================"
echo -e "${GREEN_COLOR}✅ Соответствует: $TOTAL_PASS${NC}"
echo -e "${RED_COLOR}❌ Не соответствует: $TOTAL_FAIL${NC}"
echo -e "${YELLOW_COLOR}📊 Всего проверено: $(($TOTAL_PASS + $TOTAL_FAIL))${NC}"

echo ""
echo "================================================================================"
echo -e "${GREEN_COLOR}✅ Полный отчет сохранен в файл: $OUTPUT_TXT${NC}"
echo -e "${GREEN_COLOR}✅ Отчет по аудиту сохранен в файл: $OUTPUT_MD${NC}"
echo "📁 Путь: $(pwd)/$OUTPUT_MD"
echo "================================================================================"
echo -e "${YELLOW_COLOR}Для просмотра отчета:${NC}"
echo "cat $OUTPUT_MD | less -R"
echo ""
echo -e "${YELLOW_COLOR}Для конвертации в HTML или PDF:${NC}"
echo "pandoc $OUTPUT_MD -o pg_audit_report.html --toc"
echo "pandoc $OUTPUT_MD -o pg_audit_report.pdf --toc"
echo "================================================================================"