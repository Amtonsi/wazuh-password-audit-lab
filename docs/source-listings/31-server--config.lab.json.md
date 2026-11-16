# `server/config.lab.json`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/server/config.lab.json). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Дополнительный заполненный пример основного конфига с retention_keep_generations=3, соответствующим выбранному лабораторному режиму.

**Применение.** Перед применением сверяем адрес Indexer, CA и пути; затем сохраняем как config.json с правами 0600.

**Особенности.** Используем заполненный пример конфигурации лаборатории. Это не выгрузка защищённого рабочего config.json; применение примера к серверу выполняем отдельно.

**Происхождение.** Заполненный пример конфигурации лаборатории.

**Кодировка оригинала:** UTF-8 без BOM. **Объём:** 18 строк.

**SHA256 оригинала:** `8c999f08ad426c2f0c8fa946aa3b4ddc95d42e61871b648f0ab8fb70c2104a69`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```json
{
  "indexer_url": "https://127.0.0.1:9200",
  "auth_file": "/etc/wazuh-password-audit/indexer-auth.json",
  "ca_file": "/etc/wazuh-indexer/certs/root-ca.pem",
  "allow_insecure_tls": false,
  "source_indices": "wazuh-archives-*",
  "target_alias": "lab-password-audit-current",
  "target_prefix": "lab-password-audit-state-v2",
  "inventory_file": "/etc/wazuh-password-audit/expected-agents.json",
  "max_age_seconds": 7200,
  "future_tolerance_seconds": 300,
  "publication_ttl_seconds": 300,
  "http_timeout_seconds": 30,
  "max_users_per_host": 10000,
  "bulk_batch_size": 500,
  "retention_keep_generations": 3,
  "lock_file": "/run/wazuh-password-audit.lock"
}
```
