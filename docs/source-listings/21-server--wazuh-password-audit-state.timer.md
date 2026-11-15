# `server/wazuh-password-audit-state.timer`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/server/wazuh-password-audit-state.timer). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Минутный таймер регулярного обновления серверного представления.

**Применение.** После установки выполняем systemctl daemon-reload и systemctl enable --now wazuh-password-audit-state.timer.

**Особенности.** Первый запуск через минуту после загрузки, случайная задержка до 10 секунд. Этот таймер не запускает Windows-сборщики; на АРМ действует собственный Планировщик.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-8 без BOM. **Объём:** 12 строк.

**SHA256 оригинала:** `32ddc061ae61e15f0274f6ba41df3e6b54a625d459e52f50e2db84689d15fbaa`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```ini
[Unit]
Description=Refresh local password audit state every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
RandomizedDelaySec=10s
Persistent=true
Unit=wazuh-password-audit-state.service

[Install]
WantedBy=timers.target
```
