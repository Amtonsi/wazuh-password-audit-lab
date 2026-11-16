# Скрипты, конфигурации и код дашборда

В каталоге [`code`](../code/) размещены полные файлы комплекта. Они скопированы побайтно: сохранены исходные кодировки, окончания строк и исполняемый код. Для каждого файла ниже указаны назначение, порядок применения и особенности. Контрольные суммы находятся в [`code/SHA256SUMS.txt`](../code/SHA256SUMS.txt).

Комплект содержит **32 файла и 7 310 строк**: 30 файлов проверенного набора и два отдельно обозначенных заполненных примера для лаборатории. Кодировка указана для оригинального файла, а не для веб-страницы GitHub. При сохранении VBS используем исходный UTF-16LE с BOM; для CMD — OEM866.

Для просмотра кода непосредственно в GitHub у каждого оригинала есть отдельный полный [UTF-8-листинг](source-listings/). Это представление удобно для VBS в UTF-16LE и CMD в OEM866: в нём приведены весь код, назначение и особенности. Оригинальные исполняемые файлы и их кодировки находятся в `code/`; листинги их не заменяют.

## Выбираем порядок установки

| Ситуация | Используем | Что получаем |
|---|---|---|
| Новый АРМ Windows 7/10/11 | [`deploy-windows.ps1`](../code/deploy-windows.ps1) или его [`launch-setup.vbs`](../code/launch-setup.vbs) | Агент, источник JSONL, защищённый сборщик и задача SYSTEM |
| Агент Windows 7/10/11 уже подготовлен, задачи аудита ещё нет | [`install-task.ps1`](../code/install-task.ps1) | Сборщик и задача; источник JSONL подключаем отдельно |
| Лабораторная XP с работающим агентом и прежней задачей v1 | [`finish-xp-audit.vbs`](../code/finish-xp-audit.vbs) | Отдельная задача WazuhPasswordAuditV2; прежняя задача сохранена |
| Проверяем готовый стенд | Запрос состояния службы, задачи и последнего `run_id` по [статье](../article.md) | Проверка без повторного развёртывания |

Установочные сценарии применяем при соответствующем этапе развёртывания. Существующие задания и ключи рассматриваем до замены. Рабочие ключи агента и согласованный MSI передаём новому АРМ отдельно; публичный репозиторий их не содержит.

Вспомогательные `deploy-xp.vbs` и `install-task-xp.cmd` описаны в конце каталога. Они относятся к иным этапам первоначальной миграции и не заменяют итоговый порядок с `finish-xp-audit.vbs`.

## Быстрый указатель

| Оригинал | Полный читаемый листинг | Назначение |
|---|---|---|
| [`collect-password-audit.ps1`](../code/collect-password-audit.ps1) | [Читаемый листинг](source-listings/01-collect-password-audit.ps1.md) | Получаем и оцениваем метаданные локальных пользователей Windows 7/10/11. Записываем пользовательские строки и завершающую сводку JSONL. |
| [`PasswordAudit.Native.cs`](../code/PasswordAudit.Native.cs) | [Читаемый листинг](source-listings/02-PasswordAudit.Native.cs.md) | Модуль Windows API для PowerShell-сборщика: получаем пользователей, SID, возраст и флаги, признаки интернет-идентичности и параметры локальной политики. |
| [`collect-password-audit-xp.vbs`](../code/collect-password-audit-xp.vbs) | [Читаемый листинг](source-listings/03-collect-password-audit-xp.vbs.md) | Получаем метаданные локальных пользователей XP через доступные старой Windows интерфейсы и записываем JSONL v2. |
| [`deploy-windows.ps1`](../code/deploy-windows.ps1) | [Читаемый листинг](source-listings/04-deploy-windows.ps1.md) | Комплексно развёртываем Wazuh Agent и сборщик Windows 7/10/11, добавляем источник JSONL, защищаем каталог и создаём задачу SYSTEM. |
| [`install-task.ps1`](../code/install-task.ps1) | [Читаемый листинг](source-listings/05-install-task.ps1.md) | Размещаем PowerShell-сборщик и Native.cs в защищённом каталоге и создаём WazuhPasswordAudit от SYSTEM. |
| [`launch-setup.vbs`](../code/launch-setup.vbs) | [Читаемый листинг](source-listings/06-launch-setup.vbs.md) | Запускаем deploy-windows.ps1 с повышением прав и независимым ранним журналом, ожидаем exit code и открываем итоговый TXT. |
| [`finish-xp-audit.vbs`](../code/finish-xp-audit.vbs) | [Читаемый листинг](source-listings/07-finish-xp-audit.vbs.md) | Завершаем подключение аудита v2 на XP: сохраняем конфиг, подключаем JSONL и создаём отдельную WazuhPasswordAuditV2 от SYSTEM каждый час. |
| [`wazuh-localfile.xml`](../code/wazuh-localfile.xml) | [Читаемый листинг](source-listings/10-wazuh-localfile.xml.md) | Блок чтения дневных JSONL-файлов аудита паролей. |
| [`wazuh-group-agent.conf.example`](../code/wazuh-group-agent.conf.example) | [Читаемый листинг](source-listings/11-wazuh-group-agent.conf.example.md) | Пример централизованного подключения JSONL через группу Windows-агентов. |
| [`indexer-template.http`](../code/indexer-template.http) | [Читаемый листинг](source-listings/12-indexer-template.http.md) | Полный запрос создания шаблона типов data.password_audit_v2 для архивных и alert-индексов. |
| [`existing-index-mapping.json`](../code/existing-index-mapping.json) | [Читаемый листинг](source-listings/13-existing-index-mapping.json.md) | Полное тело расширения mapping уже существующего дневного индекса полями password_audit_v2. |
| [`queries.http`](../code/queries.http) | [Читаемый листинг](source-listings/14-queries.http.md) | Диагностические запросы последних сводок по агентам и mapping нового пространства полей. |
| [`server/materialize_password_state.py`](../code/server/materialize_password_state.py) | [Читаемый листинг](source-listings/15-server--materialize_password_state.py.md) | Формируем текущее состояние АРМ и пользователей из archives, проверяем полноту, SID, run_id, свежесть и ошибки, атомарно публикуем alias. |
| [`server/config.example.json`](../code/server/config.example.json) | [Читаемый листинг](source-listings/16-server--config.example.json.md) | Исходный пример подключения к Indexer, путей, имён индексов, сроков актуальности и хранения поколений. |
| [`server/config.lab.json`](../code/server/config.lab.json) | [Читаемый листинг](source-listings/31-server--config.lab.json.md) | Дополнительный заполненный пример основного конфига с retention_keep_generations=3, соответствующим выбранному лабораторному режиму. |
| [`server/expected-agents.example.json`](../code/server/expected-agents.example.json) | [Читаемый листинг](source-listings/17-server--expected-agents.example.json.md) | Исходный пример реестра ожидаемых АРМ для расчёта охвата и отсутствующих снимков. |
| [`server/expected-agents.lab.json`](../code/server/expected-agents.lab.json) | [Читаемый листинг](source-listings/32-server--expected-agents.lab.json.md) | Дополнительный заполненный пример реестра всех четырёх АРМ лаборатории. |
| [`server/indexer-auth.example.json`](../code/server/indexer-auth.example.json) | [Читаемый листинг](source-listings/18-server--indexer-auth.example.json.md) | Шаблон защищённого файла учётных данных Indexer; содержит только заглушки. |
| [`server/current-index-mapping.json`](../code/server/current-index-mapping.json) | [Читаемый листинг](source-listings/19-server--current-index-mapping.json.md) | Справочный экспорт строгой схемы производного индекса с типами keyword, date, boolean и long. |
| [`server/wazuh-password-audit-state.service`](../code/server/wazuh-password-audit-state.service) | [Читаемый листинг](source-listings/20-server--wazuh-password-audit-state.service.md) | Служба systemd oneshot для однократного построения текущего представления с ограничениями доступа к файловой системе. |
| [`server/wazuh-password-audit-state.timer`](../code/server/wazuh-password-audit-state.timer) | [Читаемый листинг](source-listings/21-server--wazuh-password-audit-state.timer.md) | Минутный таймер регулярного обновления серверного представления. |
| [`dashboard/builder.py`](../code/dashboard/builder.py) | [Читаемый листинг](source-listings/22-dashboard--builder.py.md) | Генерируем три спецификации Vega, общий NDJSON saved objects и манифест средствами Python 3. |
| [`dashboard/KPI.vega.json`](../code/dashboard/KPI.vega.json) | [Читаемый листинг](source-listings/23-dashboard--KPI.vega.json.md) | Полный код четырёх карточек: охват АРМ, превышения возраста, индивидуальная бессрочность и отсутствие свежих полных данных. |
| [`dashboard/HOSTS.vega.json`](../code/dashboard/HOSTS.vega.json) | [Читаемый листинг](source-listings/24-dashboard--HOSTS.vega.json.md) | Полный код таблицы АРМ: ОС, охват, время, количество пользователей, максимальный срок политики и состояние сбора. |
| [`dashboard/USERS.vega.json`](../code/dashboard/USERS.vega.json) | [Читаемый листинг](source-listings/25-dashboard--USERS.vega.json.md) | Полный код таблицы пользователей с возрастом, порогом, бессрочностью, признаками истечения и цветовой индикацией. |
| [`dashboard/Wazuh-Password-Audit-v2.ndjson`](../code/dashboard/Wazuh-Password-Audit-v2.ndjson) | [Читаемый листинг](source-listings/26-dashboard--Wazuh-Password-Audit-v2.ndjson.md) | Полный импортируемый экспорт четырёх объектов: трёх визуализаций и dashboard. |
| [`dashboard/manifest.json`](../code/dashboard/manifest.json) | [Читаемый листинг](source-listings/27-dashboard--manifest.json.md) | Манифест локальной сборки: ID, количество объектов и панелей, alias и ограничение выборки. |
| [`verify-package.ps1`](../code/verify-package.ps1) | [Читаемый листинг](source-listings/28-verify-package.ps1.md) | Чистые проверки расчётов, JSON, native-layout, компиляции C#, XML задачи и XP self-tests. |
| [`server/test_materialize_password_state.py`](../code/server/test_materialize_password_state.py) | [Читаемый листинг](source-listings/29-server--test_materialize_password_state.py.md) | Модульные проверки снимков, свежести, охвата, alias и retention на фикстурах и имитаторе Indexer. |
| [`dashboard/validate.cjs`](../code/dashboard/validate.cjs) | [Читаемый листинг](source-listings/30-dashboard--validate.cjs.md) | Проверки расчётов и состояний Vega, форм hits.total, ограничений, ссылок объектов и параметров обновления. |
| [`deploy-xp.vbs`](../code/deploy-xp.vbs) | [Читаемый листинг](source-listings/08-deploy-xp.vbs.md) | Вспомогательный сценарий первоначальной миграции XP: подготавливаем каталог и конфиг v2, анализируем прежнюю задачу, сохраняем резервные материалы. |
| [`install-task-xp.cmd`](../code/install-task-xp.cmd) | [Читаемый листинг](source-listings/09-install-task-xp.cmd.md) | Создаём первоначальную WazuhPasswordAudit на XP при её отсутствии и уже размещённом VBS-сборщике. |

## Сборщики

### `collect-password-audit.ps1`

[Оригинальный файл](../code/collect-password-audit.ps1) · [Полный читаемый листинг](source-listings/01-collect-password-audit.ps1.md).

**Назначение.** Получаем и оцениваем метаданные локальных пользователей Windows 7/10/11. Записываем пользовательские строки и завершающую сводку JSONL.

**Применение.** Размещаем рядом PasswordAudit.Native.cs. Контроль: powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SIEM-Audit\Password\collect-password-audit.ps1 -ThresholdDays 60. Самопроверка: добавляем -SelfTest.

**Особенности.** Содержимое и хеши паролей не извлекаем. Неизвестные свойства не подменяем false; облачный пароль исключаем из оценки. Файл PS1 сохраняем в UTF-8 с BOM для старого Windows PowerShell.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 с BOM; 168 строк.

### `PasswordAudit.Native.cs`

[Оригинальный файл](../code/PasswordAudit.Native.cs) · [Полный читаемый листинг](source-listings/02-PasswordAudit.Native.cs.md).

**Назначение.** Модуль Windows API для PowerShell-сборщика: получаем пользователей, SID, возраст и флаги, признаки интернет-идентичности и параметры локальной политики.

**Применение.** Располагаем рядом с collect-password-audit.ps1; сборщик загружает модуль через Add-Type. Самостоятельно программу из файла не запускаем.

**Особенности.** Читаем NetUserEnum, NetUserGetInfo и NetUserModalsGet. Структуры зависят от разрядности; их x64/x86-разметка проверена. Минимальная длина политики не доказывает длину установленного пароля.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 142 строк.

### `collect-password-audit-xp.vbs`

[Оригинальный файл](../code/collect-password-audit-xp.vbs) · [Полный читаемый листинг](source-listings/03-collect-password-audit-xp.vbs.md).

**Назначение.** Получаем метаданные локальных пользователей XP через доступные старой Windows интерфейсы и записываем JSONL v2.

**Применение.** Контроль: cscript.exe //Nologo C:\SIEM-Audit\Password\collect-password-audit-xp.vbs /threshold:60. Самопроверка: /selftest.

**Особенности.** Основной сбор не меняет пароли и политику. Режим /secure отдельно настраивает ACL рабочего каталога. Общую парольную политику этот адаптер не собирает. Исполнитель из окружения является необязательной метаинформацией; файл VBS сохраняем в UTF-16LE с BOM.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-16 с BOM; 480 строк.


## Основное развёртывание

### `deploy-windows.ps1`

[Оригинальный файл](../code/deploy-windows.ps1) · [Полный читаемый листинг](source-listings/04-deploy-windows.ps1.md).

**Назначение.** Комплексно развёртываем Wazuh Agent и сборщик Windows 7/10/11, добавляем источник JSONL, защищаем каталог и создаём задачу SYSTEM.

**Применение.** Для нового АРМ выполняем от администратора: powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Install\windows-password-audit-v2\deploy-windows.ps1 -Manager 192.168.179.20 -ThresholdDays 60. Рядом размещаем согласованный MSI и индивидуальный agent-client.keys.

**Особенности.** Существующие ключ и задачу по умолчанию сохраняем. Перед заменой конфигурации создаём backup; после старта ожидаем источник и соединение. При остановке агента восстанавливаем конфиг. На уже работающем стенде повторную установку не выполняем как проверку.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 с BOM; 447 строк.

### `install-task.ps1`

[Оригинальный файл](../code/install-task.ps1) · [Полный читаемый листинг](source-listings/05-install-task.ps1.md).

**Назначение.** Размещаем PowerShell-сборщик и Native.cs в защищённом каталоге и создаём WazuhPasswordAudit от SYSTEM.

**Применение.** Применяем при уже установленном агенте: powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Install\windows-password-audit-v2\install-task.ps1 -ThresholdDays 60.

**Особенности.** Регистрацию агента и ossec.conf этот файл не настраивает. Существующую одноимённую задачу не заменяет. Не запускаем дополнительно после полноценного deploy-windows.ps1.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 с BOM; 103 строк.

### `launch-setup.vbs`

[Оригинальный файл](../code/launch-setup.vbs) · [Полный читаемый листинг](source-listings/06-launch-setup.vbs.md).

**Назначение.** Запускаем deploy-windows.ps1 с повышением прав и независимым ранним журналом, ожидаем exit code и открываем итоговый TXT.

**Применение.** Для нового АРМ запускаем файл из подготовленного комплекта Windows 7/10/11. Подтверждаем штатный UAC.

**Особенности.** Пароль администратора в сценарии отсутствует. Журнал создаётся в TEMP до запуска bootstrap; stdout/stderr и коды ошибок сохраняются. Read-only DVD не скрывает раннюю ошибку. Источник VBS — UTF-16LE с BOM.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-16 с BOM; 640 строк.

### `finish-xp-audit.vbs`

[Оригинальный файл](../code/finish-xp-audit.vbs) · [Полный читаемый листинг](source-listings/07-finish-xp-audit.vbs.md).

**Назначение.** Завершаем подключение аудита v2 на XP: сохраняем конфиг, подключаем JSONL и создаём отдельную WazuhPasswordAuditV2 от SYSTEM каждый час.

**Применение.** Для первоначального завершения настройки запускаем от администратора: cscript.exe //Nologo C:\Install\windows-password-audit-v2\finish-xp-audit.vbs. Самопроверка: /selftest.

**Особенности.** Старую v1-задачу и её сценарий сохраняем. Имя V2 проверяем до изменений. Совпавшая существующая задача без доказанного расписания даёт needs_review. После создания запускаем через Планировщик и ожидаем новый полный run_id. Отсутствие необязательного executor-окружения не означает неполноту пользовательского снимка.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-16 с BOM; 782 строк.


## Конфигурация Wazuh и Indexer

### `wazuh-localfile.xml`

[Оригинальный файл](../code/wazuh-localfile.xml) · [Полный читаемый листинг](source-listings/10-wazuh-localfile.xml.md).

**Назначение.** Блок чтения дневных JSONL-файлов аудита паролей.

**Применение.** Объединяем один localfile с существующим ossec_config агента и применяем конфигурацию.

**Особенности.** Не заменяем этим фрагментом весь ossec.conf. Тот же источник не дублируем в локальном и групповом конфиге.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 6 строк.

### `wazuh-group-agent.conf.example`

[Оригинальный файл](../code/wazuh-group-agent.conf.example) · [Полный читаемый листинг](source-listings/11-wazuh-group-agent.conf.example.md).

**Назначение.** Пример централизованного подключения JSONL через группу Windows-агентов.

**Применение.** Объединяем с существующим agent.conf нужной группы; проверяем получение агентами.

**Особенности.** Файл не устанавливает сборщики и задания. На XP отдельно проверяем применение общих конфигураций; в лаборатории источник можно оставить локальным.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 8 строк.

### `indexer-template.http`

[Оригинальный файл](../code/indexer-template.http) · [Полный читаемый листинг](source-listings/12-indexer-template.http.md).

**Назначение.** Полный запрос создания шаблона типов data.password_audit_v2 для архивных и alert-индексов.

**Применение.** Выполняем запрос в Dev Tools согласованного Indexer до создания новых дневных индексов.

**Особенности.** Существующие индексы проверяем отдельно. Legacy template имеет order=110; при composable templates учитываем действительные приоритеты. Старый namespace v1 не меняем.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 145 строк.

### `existing-index-mapping.json`

[Оригинальный файл](../code/existing-index-mapping.json) · [Полный читаемый листинг](source-listings/13-existing-index-mapping.json.md).

**Назначение.** Полное тело расширения mapping уже существующего дневного индекса полями password_audit_v2.

**Применение.** Используем как тело PUT /<фактический_индекс>/_mapping и проверяем результат GET mapping.

**Особенности.** Имя индекса определяем фактически. Этот файл не меняет тип уже существующего несовместимого поля; отдельный namespace v2 предотвращает конфликт с v1.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 137 строк.

### `queries.http`

[Оригинальный файл](../code/queries.http) · [Полный читаемый листинг](source-listings/14-queries.http.md).

**Назначение.** Диагностические запросы последних сводок по агентам и mapping нового пространства полей.

**Применение.** Выполняем отдельные GET-запросы в Dev Tools.

**Особенности.** Composite-список продолжаем с after_key для большого парка. Не фильтруем заранее только успешные снимки: более поздняя ошибка должна оставаться видимой.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 25 строк.


## Обработчик текущего состояния

### `server/materialize_password_state.py`

[Оригинальный файл](../code/server/materialize_password_state.py) · [Полный читаемый листинг](source-listings/15-server--materialize_password_state.py.md).

**Назначение.** Формируем текущее состояние АРМ и пользователей из archives, проверяем полноту, SID, run_id, свежесть и ошибки, атомарно публикуем alias.

**Применение.** На Linux выполняем: python3 /opt/wazuh-password-audit/materialize_password_state.py --config /etc/wazuh-password-audit/config.json --once. Требуется Python 3.8+; внешние Python-библиотеки не нужны.

**Особенности.** Источник использует data.password_audit_v2; результат имеет плоские поля и document_kind=host/user. К Windows по сети не подключаемся. Дашборд учитывает valid_until и неполные последние снимки.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 539 строк.

### `server/config.example.json`

[Оригинальный файл](../code/server/config.example.json) · [Полный читаемый листинг](source-listings/16-server--config.example.json.md).

**Назначение.** Исходный пример подключения к Indexer, путей, имён индексов, сроков актуальности и хранения поколений.

**Применение.** Копируем в /etc/wazuh-password-audit/config.json и заполняем параметры; устанавливаем root:root и 0600.

**Особенности.** В исходном примере retention_keep_generations=0 отключает очистку. В лаборатории используем 3. Для удобства добавлен отдельный config.lab.json с этим значением; оригинал не изменён. TLS-проверку сохраняем включённой.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 18 строк.

### `server/config.lab.json`

[Оригинальный файл](../code/server/config.lab.json) · [Полный читаемый листинг](source-listings/31-server--config.lab.json.md).

**Назначение.** Дополнительный заполненный пример основного конфига с retention_keep_generations=3, соответствующим выбранному лабораторному режиму.

**Применение.** Перед применением сверяем адрес Indexer, CA и пути; затем сохраняем как config.json с правами 0600.

**Особенности.** Используем заполненный пример конфигурации лаборатории. Это не выгрузка защищённого рабочего config.json; применение примера к серверу выполняем отдельно.

**Происхождение и формат.** Заполненный пример, подготовленный для этой лаборатории. UTF-8 без BOM; 18 строк.

### `server/expected-agents.example.json`

[Оригинальный файл](../code/server/expected-agents.example.json) · [Полный читаемый листинг](source-listings/17-server--expected-agents.example.json.md).

**Назначение.** Исходный пример реестра ожидаемых АРМ для расчёта охвата и отсутствующих снимков.

**Применение.** Копируем в /etc/wazuh-password-audit/expected-agents.json; заполняем массив фактических agent_id, agent_name, os и expected.

**Особенности.** Оригинал содержит только агента 001. Для лаборатории добавлен отдельный expected-agents.lab.json на четыре ID. ID сохраняем строкой с ведущими нулями. Узлы вне реестра не увеличивают число ожидаемых.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 3 строк.

### `server/expected-agents.lab.json`

[Оригинальный файл](../code/server/expected-agents.lab.json) · [Полный читаемый листинг](source-listings/32-server--expected-agents.lab.json.md).

**Назначение.** Дополнительный заполненный пример реестра всех четырёх АРМ лаборатории.

**Применение.** После сверки ID используем как expected-agents.json.

**Особенности.** Используем заполненный реестр четырёх АРМ лаборатории. Перед переносом на другой стенд заменяем ID и имена его фактическими регистрациями.

**Происхождение и формат.** Заполненный пример, подготовленный для этой лаборатории. UTF-8 без BOM; 26 строк.

### `server/indexer-auth.example.json`

[Оригинальный файл](../code/server/indexer-auth.example.json) · [Полный читаемый листинг](source-listings/18-server--indexer-auth.example.json.md).

**Назначение.** Шаблон защищённого файла учётных данных Indexer; содержит только заглушки.

**Применение.** Заполняем локально /etc/wazuh-password-audit/indexer-auth.json и задаём root:root, 0600. Путь указываем в auth_file.

**Особенности.** Действительные секреты не входят в сборник. Права учётной записи должны позволять чтение источника, запись собственных производных индексов, переключение alias и retention при его включении.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 4 строк.

### `server/current-index-mapping.json`

[Оригинальный файл](../code/server/current-index-mapping.json) · [Полный читаемый листинг](source-listings/19-server--current-index-mapping.json.md).

**Назначение.** Справочный экспорт строгой схемы производного индекса с типами keyword, date, boolean и long.

**Применение.** Используем при изучении структуры и запросах document_kind=host или user.

**Особенности.** Materializer не читает этот файл: схема создаётся его функцией mappings(). Изменение только JSON не меняет рабочую схему. Здесь применяются плоские поля, а не data.password_audit_v2.*.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 159 строк.

### `server/wazuh-password-audit-state.service`

[Оригинальный файл](../code/server/wazuh-password-audit-state.service) · [Полный читаемый листинг](source-listings/20-server--wazuh-password-audit-state.service.md).

**Назначение.** Служба systemd oneshot для однократного построения текущего представления с ограничениями доступа к файловой системе.

**Применение.** Устанавливаем в /etc/systemd/system; перечитываем systemd. Разовый запуск: systemctl start wazuh-password-audit-state.service.

**Особенности.** Проверяем пути ExecStart и конфигурации. Успешно завершённая oneshot-служба может быть inactive; контролируем Result и journal.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 20 строк.

### `server/wazuh-password-audit-state.timer`

[Оригинальный файл](../code/server/wazuh-password-audit-state.timer) · [Полный читаемый листинг](source-listings/21-server--wazuh-password-audit-state.timer.md).

**Назначение.** Минутный таймер регулярного обновления серверного представления.

**Применение.** После установки выполняем systemctl daemon-reload и systemctl enable --now wazuh-password-audit-state.timer.

**Особенности.** Первый запуск через минуту после загрузки, случайная задержка до 10 секунд. Этот таймер не запускает Windows-сборщики; на АРМ действует собственный Планировщик.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 12 строк.


## Код дашборда

### `dashboard/builder.py`

[Оригинальный файл](../code/dashboard/builder.py) · [Полный читаемый листинг](source-listings/22-dashboard--builder.py.md).

**Назначение.** Генерируем три спецификации Vega, общий NDJSON saved objects и манифест средствами Python 3.

**Применение.** Из каталога dashboard выполняем python builder.py; затем проверяем результат.

**Особенности.** Перезаписывает генерируемые локальные файлы, но не изменяет Wazuh. Воспроизводимые правки оформления вносим в builder.py.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 213 строк.

### `dashboard/KPI.vega.json`

[Оригинальный файл](../code/dashboard/KPI.vega.json) · [Полный читаемый листинг](source-listings/23-dashboard--KPI.vega.json.md).

**Назначение.** Полный код четырёх карточек: охват АРМ, превышения возраста, индивидуальная бессрочность и отсутствие свежих полных данных.

**Применение.** Используем в Vega 5 либо импортируем в составе общего NDJSON. Источник: lab-password-audit-current.

**Особенности.** Счётчики пользователей относятся к свежим полным ожидаемым АРМ. Явный never_expires отличается от общей неограниченной политики; усечённую выборку не выдаём за полную.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 367 строк.

### `dashboard/HOSTS.vega.json`

[Оригинальный файл](../code/dashboard/HOSTS.vega.json) · [Полный читаемый листинг](source-listings/24-dashboard--HOSTS.vega.json.md).

**Назначение.** Полный код таблицы АРМ: ОС, охват, время, количество пользователей, максимальный срок политики и состояние сбора.

**Применение.** Используем как Vega-панель на текущем alias.

**Особенности.** Состояние отражает результаты сбора. При истечении valid_until строка становится устаревшей; неизвестную политику XP не заменяем нулём.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 834 строк.

### `dashboard/USERS.vega.json`

[Оригинальный файл](../code/dashboard/USERS.vega.json) · [Полный читаемый листинг](source-listings/25-dashboard--USERS.vega.json.md).

**Назначение.** Полный код таблицы пользователей с возрастом, порогом, бессрочностью, признаками истечения и цветовой индикацией.

**Применение.** Используем как Vega 5-панель на текущем alias; таблица содержит локальную пагинацию.

**Особенности.** Зелёный статус не подтверждает сложность пароля. Отключённые, облачные и неполные записи оцениваются отдельно. Пользователь идентифицируется по agent.id и SID.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 1005 строк.

### `dashboard/Wazuh-Password-Audit-v2.ndjson`

[Оригинальный файл](../code/dashboard/Wazuh-Password-Audit-v2.ndjson) · [Полный читаемый листинг](source-listings/26-dashboard--Wazuh-Password-Audit-v2.ndjson.md).

**Назначение.** Полный импортируемый экспорт четырёх объектов: трёх визуализаций и dashboard.

**Применение.** Импортируем через Saved objects в используемый интерфейсом tenant; ID dashboard: lab-password-audit-v2-overview.

**Особенности.** Импорт не устанавливает сборщики и не наполняет alias. До замены своих объектов сохраняем экспорт. Общие timepicker и DQL к текущим Vega-панелям не применяются. Формат NDJSON сохраняем: по одному объекту на строку.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 4 строк.

### `dashboard/manifest.json`

[Оригинальный файл](../code/dashboard/manifest.json) · [Полный читаемый листинг](source-listings/27-dashboard--manifest.json.md).

**Назначение.** Манифест локальной сборки: ID, количество объектов и панелей, alias и ограничение выборки.

**Применение.** Используем для проверки состава перед импортом.

**Особенности.** Это не отчёт о текущем внедрении. live_imported=false относится к стадии сборки и не опровергает выполненный позднее импорт.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 10 строк.


## Проверки

### `verify-package.ps1`

[Оригинальный файл](../code/verify-package.ps1) · [Полный читаемый листинг](source-listings/28-verify-package.ps1.md).

**Назначение.** Чистые проверки расчётов, JSON, native-layout, компиляции C#, XML задачи и XP self-tests.

**Применение.** Запускаем Windows PowerShell 5.1 x64/x86: powershell.exe -NoProfile -ExecutionPolicy Bypass -File verify-package.ps1.

**Особенности.** Не перечисляет реальных пользователей, не регистрирует задачи и не меняет ACL. Не предназначен для запуска в PowerShell 2.0; успешные fixtures не заменяют живую интеграцию.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 с BOM; 68 строк.

### `server/test_materialize_password_state.py`

[Оригинальный файл](../code/server/test_materialize_password_state.py) · [Полный читаемый листинг](source-listings/29-server--test_materialize_password_state.py.md).

**Назначение.** Модульные проверки снимков, свежести, охвата, alias и retention на фикстурах и имитаторе Indexer.

**Применение.** Выполняем python3 server/test_materialize_password_state.py; основной Python-модуль располагаем рядом.

**Особенности.** К рабочему SIEM не подключается и данные не публикует. Проверки не заменяют сопоставление реального run_id в архиве, индексе и current alias.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 237 строк.

### `dashboard/validate.cjs`

[Оригинальный файл](../code/dashboard/validate.cjs) · [Полный читаемый листинг](source-listings/30-dashboard--validate.cjs.md).

**Назначение.** Проверки расчётов и состояний Vega, форм hits.total, ограничений, ссылок объектов и параметров обновления.

**Применение.** После сборки выполняем node validate.cjs с доступным модулем Vega.

**Особенности.** Путь require к Vega привязан к исходной рабочей станции и при переносе требует настройки. Проверочные SVG используют искусственные данные; это не скриншоты Wazuh.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-8 без BOM; 56 строк.


## Вспомогательная миграция XP

### `deploy-xp.vbs`

[Оригинальный файл](../code/deploy-xp.vbs) · [Полный читаемый листинг](source-listings/08-deploy-xp.vbs.md).

**Назначение.** Вспомогательный сценарий первоначальной миграции XP: подготавливаем каталог и конфиг v2, анализируем прежнюю задачу, сохраняем резервные материалы.

**Применение.** Изучаем и применяем только при соответствующем сценарии первоначальной миграции. В выполненном итоговом порядке XP используем finish-xp-audit.vbs.

**Особенности.** Может работать с подтверждённой legacy-задачей и wrapper прежнего сборщика; неизвестную задачу оставляет для проверки. Поэтому этот файл не считаем взаимозаменяемым с финальным finish-сценарием. Исходник сохранён полностью.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. UTF-16 с BOM; 598 строк.

### `install-task-xp.cmd`

[Оригинальный файл](../code/install-task-xp.cmd) · [Полный читаемый листинг](source-listings/09-install-task-xp.cmd.md).

**Назначение.** Создаём первоначальную WazuhPasswordAudit на XP при её отсутствии и уже размещённом VBS-сборщике.

**Применение.** Запускаем CMD от администратора на подходящем новом XP-узле. Проверяем работающую службу Schedule.

**Особенности.** Использует старое имя WazuhPasswordAudit; при существующей задаче останавливается. Для текущей лаборатории с сохранением v1 выбираем finish-xp-audit.vbs и отдельное имя V2. CMD сохраняем в OEM866.

**Происхождение и формат.** Побайтная копия проверенного исходного комплекта. OEM866; 36 строк.


## Порядок изменения и повторной проверки

При собственной доработке сначала сохраняем исходную версию, меняем нужный модуль, выполняем профильные проверки и повторяем сквозной контроль. Затем пересчитываем контрольные суммы изменённой версии. Само совпадение SHA256 доказывает сохранность файла, но не успешное выполнение на конкретном АРМ.

Для воспроизводимой правки визуализаций меняем `dashboard/builder.py`, запускаем сборку и проверяем полученные Vega и NDJSON. До импорта сохраняем экспорт собственных объектов Wazuh. [Методы и границы проверки](reproducibility.md) приведены отдельно.
