# `server/current-index-mapping.json`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/server/current-index-mapping.json). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Справочный экспорт строгой схемы производного индекса с типами keyword, date, boolean и long.

**Применение.** Используем при изучении структуры и запросах document_kind=host или user.

**Особенности.** Materializer не читает этот файл: схема создаётся его функцией mappings(). Изменение только JSON не меняет рабочую схему. Здесь применяются плоские поля, а не data.password_audit_v2.*.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-8 без BOM. **Объём:** 159 строк.

**SHA256 оригинала:** `ad47ef4d23b31387d7190be0100010716310ce214c85958f203f9c8f6c2e8264`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```json
{
  "dynamic": "strict",
  "properties": {
    "document_kind": {
      "type": "keyword"
    },
    "agent_id": {
      "type": "keyword"
    },
    "agent_name": {
      "type": "keyword"
    },
    "agent_ip": {
      "type": "keyword"
    },
    "os": {
      "type": "keyword"
    },
    "sid": {
      "type": "keyword"
    },
    "username": {
      "type": "keyword"
    },
    "host_state": {
      "type": "keyword"
    },
    "host_state_label": {
      "type": "keyword"
    },
    "row_state": {
      "type": "keyword"
    },
    "row_state_label": {
      "type": "keyword"
    },
    "source_run_id": {
      "type": "keyword"
    },
    "accepted_run_id": {
      "type": "keyword"
    },
    "record_run_id": {
      "type": "keyword"
    },
    "collector_status": {
      "type": "keyword"
    },
    "collection_status": {
      "type": "keyword"
    },
    "policy_read_status": {
      "type": "keyword"
    },
    "exclusion_reason": {
      "type": "keyword"
    },
    "observed_at": {
      "type": "date",
      "format": "strict_date_optional_time||epoch_millis"
    },
    "received_at": {
      "type": "date",
      "format": "strict_date_optional_time||epoch_millis"
    },
    "published_at": {
      "type": "date",
      "format": "strict_date_optional_time||epoch_millis"
    },
    "valid_until": {
      "type": "date",
      "format": "strict_date_optional_time||epoch_millis"
    },
    "enabled": {
      "type": "boolean"
    },
    "never_expires": {
      "type": "boolean"
    },
    "expired_reported": {
      "type": "boolean"
    },
    "threshold_exceeded": {
      "type": "boolean"
    },
    "policy_expired_calculated": {
      "type": "boolean"
    },
    "internet_identity": {
      "type": "boolean"
    },
    "expected": {
      "type": "boolean"
    },
    "snapshot_complete": {
      "type": "boolean"
    },
    "is_current_snapshot": {
      "type": "boolean"
    },
    "policy_max_age_unlimited": {
      "type": "boolean"
    },
    "age_seconds": {
      "type": "long"
    },
    "age_days": {
      "type": "long"
    },
    "threshold_days": {
      "type": "long"
    },
    "expected_user_count": {
      "type": "long"
    },
    "emitted_user_count": {
      "type": "long"
    },
    "unknown_count": {
      "type": "long"
    },
    "excluded_count": {
      "type": "long"
    },
    "policy_max_age_seconds": {
      "type": "long"
    },
    "known_over_threshold_count": {
      "type": "long"
    },
    "retained_user_count": {
      "type": "long"
    },
    "user_count": {
      "type": "long"
    },
    "enabled_count": {
      "type": "long"
    },
    "never_expires_count": {
      "type": "long"
    },
    "over_threshold_count": {
      "type": "long"
    },
    "expired_reported_count": {
      "type": "long"
    },
    "policy_expired_count": {
      "type": "long"
    },
    "read_error": {
      "type": "text"
    },
    "snapshot_diagnostics": {
      "type": "keyword"
    }
  }
}
```
