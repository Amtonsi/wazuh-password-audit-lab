# `server/config.example.json`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/server/config.example.json). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Исходный пример подключения к Indexer, путей, имён индексов, сроков актуальности и хранения поколений.

**Применение.** Копируем в /etc/wazuh-password-audit/config.json и заполняем параметры; устанавливаем root:root и 0600.

**Особенности.** В исходном примере retention_keep_generations=0 отключает очистку. В лаборатории используем 3. Для удобства добавлен отдельный config.lab.json с этим значением; оригинал не изменён. TLS-проверку сохраняем включённой.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-8 без BOM. **Объём:** 18 строк.

**SHA256 оригинала:** `ad68b03ec1399e5240dddfa9f2418d372821c0bdee3c14fcaefa3def1395234d`.

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
  "retention_keep_generations": 0,
  "lock_file": "/run/wazuh-password-audit.lock"
}
```
