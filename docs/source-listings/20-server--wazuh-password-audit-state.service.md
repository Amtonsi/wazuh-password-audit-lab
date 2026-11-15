# `server/wazuh-password-audit-state.service`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/server/wazuh-password-audit-state.service). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Служба systemd oneshot для однократного построения текущего представления с ограничениями доступа к файловой системе.

**Применение.** Устанавливаем в /etc/systemd/system; перечитываем systemd. Разовый запуск: systemctl start wazuh-password-audit-state.service.

**Особенности.** Проверяем пути ExecStart и конфигурации. Успешно завершённая oneshot-служба может быть inactive; контролируем Result и journal.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-8 без BOM. **Объём:** 20 строк.

**SHA256 оригинала:** `16f65d2ee6c31b70c620c48bd6fa98387f7c51462f0dd598d2d3811a97f1d725`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```ini
[Unit]
Description=Materialize local password audit current state in Wazuh Indexer
After=network-online.target wazuh-indexer.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/wazuh-password-audit/materialize_password_state.py --config /etc/wazuh-password-audit/config.json --once
User=root
Group=root
UMask=0077
TimeoutStartSec=180
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run

[Install]
WantedBy=multi-user.target
```
