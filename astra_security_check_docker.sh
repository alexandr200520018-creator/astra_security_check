#!/bin/bash

# ============================================================
# НАСТРОЙКИ ПРОГРАММЫ
# ============================================================

# Файлы для отчёта
OUTPUT_MD="docker_audit_report_$(date +%Y%m%d_%H%M%S).md"
OUTPUT_TXT="docker_audit_report_$(date +%Y%m%d_%H%M%S).txt"

# Цвета для вывода на экран
HEADER_COLOR="\033[1;34m"
GREEN_COLOR="\033[0;32m"
RED_COLOR="\033[0;31m"
YELLOW_COLOR="\033[1;33m"
NC="\033[0m"

# ============================================================
# ФУНКЦИИ ДЛЯ РАБОТЫ С DOCKER
# ============================================================

# Проверка наличия Docker
check_docker_installed() {
    if command -v docker &>/dev/null; then
        echo "установлен"
    else
        echo "не установлен"
    fi
}

# Получение информации о версии
get_docker_version() {
    if command -v docker &>/dev/null; then
        docker --version 2>/dev/null | awk '{print $3}' | sed 's/,//'
    else
        echo "не установлен"
    fi
}

# Получение параметра Docker демона из daemon.json
get_daemon_param() {
    local param="$1"
    if [ -f /etc/docker/daemon.json ]; then
        local value=$(grep -o "\"$param\": *[^,}]*" /etc/docker/daemon.json 2>/dev/null | head -1 | cut -d':' -f2 | tr -d ' "')
        if [[ -n "$value" ]]; then
            echo "$value"
        else
            echo "не задан"
        fi
    else
        echo "файл отсутствует"
    fi
}

# Проверка прав на файл/директорию
check_file_permissions() {
    local file_path="$1"
    local required_perms="$2"
    local required_owner="$3"
    
    if [[ ! -e "$file_path" ]]; then
        echo "не найден"
        return
    fi
    
    local perms=$(stat -c "%a" "$file_path" 2>/dev/null)
    local owner=$(stat -c "%U" "$file_path" 2>/dev/null)
    
    if [[ "$perms" == "$required_perms" ]] && [[ "$owner" == "$required_owner" ]]; then
        echo "OK ($perms, $owner)"
    else
        echo "НЕ СООТВЕТСТВУЕТ (текущие: $perms, $owner; требуется: $required_perms, $owner)"
    fi
}

# Проверка параметров запуска контейнера
check_container_security() {
    local container_name="$1"
    local container_info=$(docker inspect "$container_name" 2>/dev/null)
    
    if [[ -z "$container_info" ]]; then
        echo "не существует"
        return
    fi
    
    local issues=()
    
    # Проверка --privileged
    if echo "$container_info" | grep -q '"Privileged": true'; then
        issues+=("запущен с --privileged")
    fi
    
    # Проверка --network host
    if echo "$container_info" | grep -q '"NetworkMode": "host"'; then
        issues+=("использует --network host")
    fi
    
    # Проверка --read-only
    if ! echo "$container_info" | grep -q '"ReadonlyRootfs": true'; then
        issues+=("не используется --read-only")
    fi
    
    # Проверка монтирования хостовых путей
    if echo "$container_info" | grep -q '"BindOptions"'; then
        issues+=("есть монтирование хостовых путей")
    fi
    
    if [[ ${#issues[@]} -eq 0 ]]; then
        echo "ОК"
    else
        echo "НЕ СООТВЕТСТВУЕТ: ${issues[*]}"
    fi
}

# Получение списка запущенных контейнеров
get_running_containers() {
    docker ps --format "{{.Names}}" 2>/dev/null
}

# Проверка наличия образов с тегом latest
check_latest_images() {
    local count=$(docker images --format "{{.Tag}}" 2>/dev/null | grep -c "^latest$")
    if [[ "$count" -gt 0 ]]; then
        echo "$count образов"
    else
        echo "отсутствуют"
    fi
}

# Проверка включения live-restore
check_live_restore() {
    if [ -f /etc/docker/daemon.json ]; then
        local value=$(get_daemon_param "live-restore")
        if [[ "$value" == "true" ]]; then
            echo "включено"
        else
            echo "отключено"
        fi
    else
        echo "не задан"
    fi
}

# Проверка использования userland-proxy
check_userland_proxy() {
    if [ -f /etc/docker/daemon.json ]; then
        local value=$(get_daemon_param "userland-proxy")
        if [[ "$value" == "false" ]]; then
            echo "отключен"
        else
            echo "включен"
        fi
    else
        echo "не задан"
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
    elif [[ "$current_value" == "не задан" ]] || [[ "$current_value" == "файл отсутствует" ]]; then
        status="НЕ СООТВЕТСТВУЕТ"
        md_status="Не соответствует"
        ((TOTAL_FAIL++))
        [[ -z "$comment" ]] && comment="Параметр не задан или не настроен."
    elif [[ "$current_value" == "не установлен" ]] || [[ "$current_value" == "не найден" ]] || [[ "$current_value" == "не существует" ]]; then
        status="НЕ ПРОВЕРЕНО"
        md_status="Не проверено"
        ((TOTAL_FAIL++))
        [[ -z "$comment" ]] && comment="Компонент отсутствует."
    elif [[ "$current_value" == *"НЕ СООТВЕТСТВУЕТ"* ]]; then
        status="НЕ СООТВЕТСТВУЕТ"
        md_status="Не соответствует"
        ((TOTAL_FAIL++))
        [[ -z "$comment" ]] && comment="$current_value"
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
echo -e "${HEADER_COLOR}🐳 Аудит безопасности Docker${NC}"
echo "========================================================================"

# Проверка наличия Docker
if ! command -v docker &>/dev/null; then
    echo -e "${RED_COLOR}❌ Ошибка: Docker не установлен.${NC}"
    echo "Установите Docker и попробуйте снова."
    exit 1
fi

# Проверка прав на запуск
if ! docker info &>/dev/null; then
    echo -e "${RED_COLOR}❌ Ошибка: Нет прав доступа к Docker.${NC}"
    echo "Запустите скрипт с правами root или добавьте пользователя в группу docker."
    exit 1
fi

echo -e "${GREEN_COLOR}✅ Docker обнаружен и доступен${NC}"
echo ""

# Инициализация файлов отчёта
> "$OUTPUT_MD"
> "$OUTPUT_TXT"

# Заголовок отчёта в MD
cat > "$OUTPUT_MD" << EOF
# Отчёт по аудиту безопасности Docker

**Дата проверки:** $(date '+%Y-%m-%d %H:%M:%S')
**Версия Docker:** $(get_docker_version)
**ОС:** $(uname -s -r)

---

## 1. Базовые настройки Docker

| Наименование параметра | Текущее значение | Требуемое значение | Статус проверки | Комментарий |
|---|---|---|---|---|
EOF

# Заголовок отчёта в TXT
cat > "$OUTPUT_TXT" << EOF
================================================================================
  Отчёт по аудиту безопасности Docker
================================================================================
Дата проверки: $(date '+%Y-%m-%d %H:%M:%S')
Версия Docker: $(get_docker_version)
ОС: $(uname -s -r)

================================================================================
  1. БАЗОВЫЕ НАСТРОЙКИ DOCKER
================================================================================
Наименование параметра                                  | Текущее значение           | Требуемое значение           | Статус проверки                 | Комментарий
--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|
EOF

# Заголовок в консоли
echo ""
echo "================================================================================"
echo -e "${HEADER_COLOR}  АУДИТ БАЗОВЫХ НАСТРОЕК DOCKER${NC}"
echo "================================================================================"
printf "${HEADER_COLOR}%-50s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-30s${NC} | ${HEADER_COLOR}%-60s${NC}\n" \
       "Наименование параметра" "Текущее значение" "Требуемое значение" "Статус проверки" "Комментарий"
echo "--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|"

# ---------- 1. Наличие Docker ----------
current=$(check_docker_installed)
audit_parameter "Установлен Docker" "$current" "установлен" ""

# ---------- 2. Версия Docker ----------
current=$(get_docker_version)
audit_parameter "Версия Docker" "$current" "20.10.0+" "Рекомендуется обновлять до актуальной"

# ---------- 3. Права на /var/lib/docker ----------
current=$(check_file_permissions "/var/lib/docker" "700" "root")
audit_parameter "Права на /var/lib/docker" "$current" "OK (700, root)" ""

# ---------- 4. Права на /etc/docker ----------
current=$(check_file_permissions "/etc/docker" "755" "root")
audit_parameter "Права на /etc/docker" "$current" "OK (755, root)" ""

# ---------- 5. live-restore ----------
current=$(check_live_restore)
audit_parameter "live-restore" "$current" "включено" ""

# ---------- 6. userland-proxy ----------
current=$(check_userland_proxy)
audit_parameter "userland-proxy (отключить)" "$current" "отключен" ""

# ---------- 7. log-driver ----------
current=$(get_daemon_param "log-driver")
audit_parameter "Драйвер логирования" "$current" "json-file или journald" ""

# ---------- 8. log-max-size ----------
current=$(get_daemon_param "log-max-size")
if [[ "$current" == "не задан" ]]; then
    audit_parameter "Максимальный размер логов" "$current" "10MB" ""
else
    audit_parameter "Максимальный размер логов" "$current" "10MB" ""
fi

# ============================================================
# РАЗДЕЛ 2: ЗАПУЩЕННЫЕ КОНТЕЙНЕРЫ
# ============================================================

echo "" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "  2. АНАЛИЗ ЗАПУЩЕННЫХ КОНТЕЙНЕРОВ" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "Наименование контейнера      | Статус безопасности" >> "$OUTPUT_TXT"
echo "-----------------------------|---------------------" >> "$OUTPUT_TXT"

cat >> "$OUTPUT_MD" << EOF

---

## 2. Анализ запущенных контейнеров

| Наименование контейнера | Статус безопасности |
|---|---|
EOF

echo ""
echo "================================================================================"
echo -e "${HEADER_COLOR}  АНАЛИЗ ЗАПУЩЕННЫХ КОНТЕЙНЕРОВ${NC}"
echo "================================================================================"
printf "${HEADER_COLOR}%-30s${NC} | ${HEADER_COLOR}%-50s${NC}\n" \
       "Наименование контейнера" "Статус безопасности"
echo "-----------------------------|--------------------------------------------------"

# Получаем список запущенных контейнеров
containers=$(docker ps --format "{{.Names}}" 2>/dev/null)
if [[ -n "$containers" ]]; then
    while IFS= read -r container; do
        current=$(check_container_security "$container")
        if [[ "$current" == "ОК" ]]; then
            status_icon="✅"
            status="ОК"
        else
            status_icon="❌"
            status="НЕ СООТВЕТСТВУЕТ"
        fi
        printf "%-30s | %s %s\n" "$container" "$status_icon" "$current"
        echo "$container | $status" >> "$OUTPUT_TXT"
        echo "| $container | $status |" >> "$OUTPUT_MD"
    done <<< "$containers"
else
    echo "Нет запущенных контейнеров" | tee -a "$OUTPUT_TXT"
    echo "| Нет запущенных контейнеров | - |" >> "$OUTPUT_MD"
fi

echo "" >> "$OUTPUT_TXT"

# ============================================================
# РАЗДЕЛ 3: ОБРАЗЫ КОНТЕЙНЕРОВ
# ============================================================

echo "" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "  3. АНАЛИЗ ОБРАЗОВ КОНТЕЙНЕРОВ" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "Наименование параметра                                  | Текущее значение           | Требуемое значение           | Статус проверки                 | Комментарий" >> "$OUTPUT_TXT"
echo "--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|" >> "$OUTPUT_TXT"

cat >> "$OUTPUT_MD" << EOF

---

## 3. Анализ образов контейнеров

| Наименование параметра | Текущее значение | Требуемое значение | Статус проверки | Комментарий |
|---|---|---|---|---|
EOF

echo ""
echo "================================================================================"
echo -e "${HEADER_COLOR}  АНАЛИЗ ОБРАЗОВ КОНТЕЙНЕРОВ${NC}"
echo "================================================================================"
printf "${HEADER_COLOR}%-50s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-30s${NC} | ${HEADER_COLOR}%-60s${NC}\n" \
       "Наименование параметра" "Текущее значение" "Требуемое значение" "Статус проверки" "Комментарий"
echo "--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|"

# ---------- 9. Образы с тегом latest ----------
current=$(check_latest_images)
audit_parameter "Образы с тегом latest" "$current" "отсутствуют" ""

# ---------- 10. Количество образов ----------
current=$(docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | wc -l)
audit_parameter "Всего образов" "$current" "не более 50" "Рекомендуется удалять неиспользуемые"

# ---------- 11. Образы без тега ----------
current=$(docker images --format "{{.Repository}}" 2>/dev/null | grep -c "^<none>$")
audit_parameter "Образы без тега (<none>)" "$current" "0" "Рекомендуется удалять такие образы"

# ============================================================
# РАЗДЕЛ 4: СЕТЕВЫЕ НАСТРОЙКИ
# ============================================================

echo "" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "  4. СЕТЕВЫЕ НАСТРОЙКИ" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "Наименование параметра                                  | Текущее значение           | Требуемое значение           | Статус проверки                 | Комментарий" >> "$OUTPUT_TXT"
echo "--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|" >> "$OUTPUT_TXT"

cat >> "$OUTPUT_MD" << EOF

---

## 4. Сетевые настройки

| Наименование параметра | Текущее значение | Требуемое значение | Статус проверки | Комментарий |
|---|---|---|---|---|
EOF

echo ""
echo "================================================================================"
echo -e "${HEADER_COLOR}  АУДИТ СЕТЕВЫХ НАСТРОЕК${NC}"
echo "================================================================================"
printf "${HEADER_COLOR}%-50s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-25s${NC} | ${HEADER_COLOR}%-30s${NC} | ${HEADER_COLOR}%-60s${NC}\n" \
       "Наименование параметра" "Текущее значение" "Требуемое значение" "Статус проверки" "Комментарий"
echo "--------------------------------------------------------|----------------------------|------------------------------|----------------------------------|-------------------------------------------------------------|"

# ---------- 12. Количество сетей ----------
current=$(docker network ls --format "{{.Name}}" 2>/dev/null | wc -l)
audit_parameter "Количество сетей Docker" "$current" "не более 10" "Рекомендуется удалять неиспользуемые сети"

# ---------- 13. Использование bridge по умолчанию ----------
bridges=$(docker network ls --filter "driver=bridge" --format "{{.Name}}" 2>/dev/null | wc -l)
current="$bridges сетей bridge"
audit_parameter "Сети типа bridge" "$current" "не более 2" ""

# ---------- 14. icc (inter-container communication) ----------
current=$(get_daemon_param "icc")
if [[ "$current" == "не задан" ]]; then
    current="true (по умолчанию)"
fi
audit_parameter "icc (общение контейнеров)" "$current" "false" ""

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

---

## 6. Рекомендации по устранению несоответствий

На основе проведённого аудита были выявлены параметры, не соответствующие требованиям безопасности. Рекомендуется:

1. **Настроить отсутствующие параметры** в файле `/etc/docker/daemon.json`
2. **Проверить права на файлы и директории** Docker
3. **Пересмотреть параметры запуска контейнеров** (избегать `--privileged`, `--network host`, `--user root`)
4. **Использовать теги версий вместо `latest`** для образов
5. **Удалить неиспользуемые образы и контейнеры**
6. **Провести повторный аудит** после внесения изменений

---

EOF

echo "" >> "$OUTPUT_TXT"
echo "================================================================================" >> "$OUTPUT_TXT"
echo "  СТАТИСТИКА АУДИТА" >> "$OUTPUT_TXT"
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
echo "pandoc $OUTPUT_MD -o docker_audit_report.html --toc"
echo "pandoc $OUTPUT_MD -o docker_audit_report.pdf --toc"
echo "================================================================================"