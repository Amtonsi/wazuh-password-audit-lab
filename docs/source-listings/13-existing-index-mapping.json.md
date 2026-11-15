# `existing-index-mapping.json`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/existing-index-mapping.json). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Полное тело расширения mapping уже существующего дневного индекса полями password_audit_v2.

**Применение.** Используем как тело PUT /<фактический_индекс>/_mapping и проверяем результат GET mapping.

**Особенности.** Имя индекса определяем фактически. Этот файл не меняет тип уже существующего несовместимого поля; отдельный namespace v2 предотвращает конфликт с v1.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-8 без BOM. **Объём:** 137 строк.

**SHA256 оригинала:** `6becb14b8d5a7c434681a5d356b2d0879824c61e74d2432df4e9435f03e1c4fa`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```json
{
  "properties": {
    "data": {
      "properties": {
        "password_audit_v2": {
          "properties": {
            "threshold_days": {
              "type": "long"
            },
            "computer": {
              "type": "keyword"
            },
            "completed_at_utc": {
              "type": "date",
              "format": "strict_date_optional_time||epoch_millis"
            },
            "enumeration_error": {
              "type": "text"
            },
            "enumeration_complete": {
              "type": "boolean"
            },
            "internet_identity": {
              "type": "boolean"
            },
            "age_days": {
              "type": "long"
            },
            "read_error": {
              "type": "text"
            },
            "policy_min_age_seconds": {
              "type": "long"
            },
            "known_enabled_count": {
              "type": "long"
            },
            "unknown_count": {
              "type": "long"
            },
            "run_id": {
              "type": "keyword"
            },
            "policy_expired_calculated": {
              "type": "boolean"
            },
            "excluded_count": {
              "type": "long"
            },
            "collection_status": {
              "type": "keyword"
            },
            "scope": {
              "type": "keyword"
            },
            "policy_min_length": {
              "type": "long"
            },
            "known_over_threshold_count": {
              "type": "long"
            },
            "observed_at_utc": {
              "type": "date",
              "format": "strict_date_optional_time||epoch_millis"
            },
            "error": {
              "type": "text"
            },
            "policy_max_age_seconds": {
              "type": "long"
            },
            "expired_reported": {
              "type": "boolean"
            },
            "policy_read_error": {
              "type": "text"
            },
            "collector_version": {
              "type": "keyword"
            },
            "identity_complete": {
              "type": "boolean"
            },
            "enabled_count": {
              "type": "long"
            },
            "schema_version": {
              "type": "long"
            },
            "exclusion_reason": {
              "type": "keyword"
            },
            "username": {
              "type": "keyword"
            },
            "policy_read_status": {
              "type": "keyword"
            },
            "policy_history_length": {
              "type": "long"
            },
            "age_seconds": {
              "type": "long"
            },
            "threshold_exceeded": {
              "type": "boolean"
            },
            "emitted_user_count": {
              "type": "long"
            },
            "kind": {
              "type": "keyword"
            },
            "over_threshold_count": {
              "type": "long"
            },
            "expected_user_count": {
              "type": "long"
            },
            "sid": {
              "type": "keyword"
            },
            "enabled": {
              "type": "boolean"
            },
            "never_expires": {
              "type": "boolean"
            },
            "policy_max_age_unlimited": {
              "type": "boolean"
            }
          }
        }
      }
    }
  }
}
```
