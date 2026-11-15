# Воспроизводимость и границы проверки

В репозитории опубликована версия комплекта, проверенная в лаборатории **15 ноября 2026 года**. Контрольная сквозная проверка выполнена в **21:17:59 по Иркутску**; соответствие ID и версий ОС дополнительно сверено в 21:35:49. Эти результаты относятся к проверенному состоянию стенда и не служат утверждением, что выключенные позднее виртуальные машины продолжают передавать данные.

## Сохранность исходников

В [`code`](../code/) находятся 32 полных файла: 30 файлов проверенного набора и два заполненных примера конфигурации лаборатории. Общий объём по исходному манифесту — 7 310 строк. При подсчёте текст декодировался с учётом BOM и кодовой страницы, окончания строк нормализовались только для подсчёта. Оригинальные файлы перенесены без преобразования байтов.

Для каждого источника сверены SHA256 исходного манифеста, SHA256 копии и непосредственное равенство байтов. Значения приведены в [`code/SHA256SUMS.txt`](../code/SHA256SUMS.txt) и в таблице ниже. `config.lab.json` и `expected-agents.lab.json` — отдельно подготовленные заполненные примеры, а не выгрузки защищённых рабочих файлов сервера.

Кодировки имеют значение при переносе: PowerShell-файлы сохранены в исходном UTF-8 с BOM, VBS — в UTF-16LE с BOM, CMD — в OEM866; остальные форматы соответствуют таблице. В Git применяется правило `code/** -text`, чтобы нормализация окончаний строк не изменила опубликованные байты. Значения таблицы сравниваем с файлами на диске, а не с HTML-представлением GitHub.

Для просмотра в GitHub подготовлены [32 полных UTF-8-листинга](source-listings/) с описаниями и ссылками на оригиналы. Текст каждого листинга сверён посимвольно с декодированным источником после снятия BOM и нормализации окончаний строк в LF. Перед закрывающим ограждением Markdown отдельно учитывается разделительный перенос строки; исходные файлы, включая отсутствие конечного LF у части JSON, не изменены. Контрольные суммы ниже относятся к оригиналам в `code/`, а не к оформленным Markdown-представлениям.

## Проверенная интеграция

| Агент | ОС | Пользователей | Включено | Старше 60 суток среди активных локальных | Индивидуальных бессрочных флагов среди активных локальных |
|---|---|---:|---:|---:|---:|
| 001 | Windows XP Professional SP2, 5.1.2600 | 5 | 2 | 0 | 2 |
| 002 | Windows 7 Ultimate, 6.1.7601 | 4 | 2 | 0 | 2 |
| 003 | Windows 10 Education, 10.0.19045.2006 | 5 | 1 | 0 | 0 |
| 004 | Windows 11 Pro, 10.0.26200.9457 | 10 | 5 | 4 | 3 |
| **Всего** | **4 АРМ** | **24** | **10** | **4** | **7** |

Одна интернет-связанная учётная запись Windows 11 исключена из оценки облачного пароля. Счётчики разных признаков могут пересекаться, поэтому их не складываем в число уникальных нарушителей.

Для каждого из четырёх агентов проверены количество пользовательских строк, завершающая сводка, уникальность SID и совпадение последнего `run_id` в физическом `archives.json`, индексе `wazuh-archives-*` и опубликованном `lab-password-audit-current`. В контрольном поколении получены четыре полных свежих узла и 24 пользовательские строки. Основные службы Wazuh и Filebeat работали, серверный таймер завершал проходы успешно, свежих ошибок Filebeat не обнаружено.

На XP установлена отдельная задача `WazuhPasswordAuditV2` с параметрами SYSTEM и HOURLY/MO 1. Создание, запрос запуска и завершение сборщика дали код 0; после запуска получен новый полный снимок. Исходный finish-отчёт имел общий `partial` только из-за отсутствующих необязательных метаданных исполнителя из окружения. Это не было ошибкой перечисления пользователей. Исходный отчёт не переписывался; в опубликованном helper неизвестное необязательное окружение оформлено отдельным предупреждением. Аттестацией Windows-токена такие поля не являются.

## Локальные проверки кода

| Область | Что выполнено | Что этим не подтверждается |
|---|---|---|
| Windows PowerShell 5.1 x64 и x86 | По 20 чистых проверок: синтаксис, расчёт порога, JSON, C# и native layout, схема задачи, XP self-tests | Сами по себе эти проверки не являются выполнением на гостевых ОС |
| Установщики и launcher | Сценарии готовности и остановки службы, обработка кодов завершения, кириллицы UTF-8 и путей с пробелом/апострофом | Не доказывают любой возможный локальный набор политик и защитных средств |
| C# | Компиляция компилятором .NET 3.5 без вызова SAM API | Не является отдельным прогоном на всех старых версиях .NET |
| Серверный обработчик | 31 проверка на фикстурах и имитаторе Indexer: полнота, свежесть, покрытие, bulk/count, alias и retention | Не заменяет реальное соединение с установленным Indexer |
| Vega и saved objects | 13 групп проверок: состояния, цвета, пустые данные, обе формы hits.total, усечение, ссылки, параметры обновления | Проверочные SVG не являются снимками действующего Wazuh |
| Реальный интерфейс Wazuh | KPI 4/4, 4 превышения, 7 бессрочных признаков и 0 АРМ без данных; таблицы, цвета и реальные скриншоты | Длительная серия самостоятельных 60-секундных обновлений отдельно не измерялась |

Исправленный установщик прошёл реальное развёртывание на Windows 7. Точная версия гостевого движка PowerShell в итоговый протокол не попала, поэтому отдельное утверждение «runtime PowerShell 2.0 полностью испытан» этому результату не приписываем.

## Как повторяем проверки

На Windows 10/11 с Windows PowerShell 5.1 открываем корень репозитория и выполняем чистую проверку комплекта:

```powershell
# Не регистрирует задачи, не меняет ACL и не перечисляет реальных пользователей.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\code\verify-package.ps1"

# Для проверки 32-битного режима используем штатный x86 Windows PowerShell.
& "$env:WINDIR\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" `
  -NoProfile -ExecutionPolicy Bypass -File ".\code\verify-package.ps1"
```

Серверные фикстуры запускаем из корня репозитория:

```bash
python3 code/server/test_materialize_password_state.py
```

Для локальных тестов визуализаций требуются Node.js и Vega 5.25.0. В сохранённом `code/dashboard/validate.cjs` путь `require` к модулю Vega указывает на исходную рабочую станцию. Перед запуском на другой машине подготавливаем соответствующую среду или явно адаптируем тест в отдельной рабочей копии и фиксируем изменение. Код теста в публикации сохранён без этой адаптации. Выполненную проверку отличаем от установки рабочего дашборда.

Генератор `code/dashboard/builder.py` перезаписывает локальные спецификации Vega, NDJSON и манифест, поэтому его запускаем в рабочей копии при осознанной сборке. Для импорта готового дашборда достаточно опубликованного NDJSON; запуск генератора не является обязательным этапом импорта.

## Проверка SHA256

На Linux переходим из корня репозитория в `code` и выполняем:

```bash
cd code
sha256sum -c SHA256SUMS.txt
```

На Windows 10/11 используем PowerShell:

```powershell
# Выполняем из корня репозитория. Читаем только файлы комплекта.
Push-Location ".\code"
try {
    foreach ($line in Get-Content -LiteralPath ".\SHA256SUMS.txt" -Encoding UTF8) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $fields = $line -split '  ', 2
        if ($fields.Count -ne 2) { throw "Некорректная строка SHA256SUMS" }
        $actual = (Get-FileHash -LiteralPath $fields[1] -Algorithm SHA256).Hash
        if ($actual -ne $fields[0]) { throw "Не совпал SHA256: $($fields[1])" }
        Write-Output "OK: $($fields[1])"
    }
}
finally {
    Pop-Location
}
```

## Ограничения результата

Пароли, их хеши и содержимое SAM не извлекались; учётные записи и парольная политика сборщиками не менялись. Возраст и флаги не доказывают длину или сложность существующего пароля. Windows Hello PIN и действительный пароль Microsoft Account в область локального SAM-аудита не входят.

Порог возраста сравниваем строго как `age_seconds > 60 * 86400`. Истечение по прочитанной локальной политике, требование Windows о смене и индивидуальный признак бессрочности являются отдельными показателями. Общая политика без максимального возраста также не равна индивидуальному флагу `never_expires`.

Адаптер XP публикует `policy_read_status=not_collected`; отсутствие локальной политики не заменяем нулевым сроком или утверждением о соответствии. На Windows 7 и 11 прочитан максимальный срок 42 суток, на Windows 10 — отсутствие ограничения. Минимальная длина и история на этих трёх АРМ равны 0; это настройки политики, а не результат анализа установленных паролей.

Новый пользовательский счётчик строим по полному последнему снимку, а не по числу событий за сутки. Учитываем свежесть исходного измерения и публикации: два часа для источника и пять минут для опубликованного представления. При остановке обновления результаты становятся устаревшими; старое зелёное состояние не сохраняется бессрочно. Параметр автообновления дашборда сохранён на 60 секунд.

## Контрольные суммы файлов

| Файл | Происхождение | Кодировка | SHA256 |
|---|---|---|---|
| [`collect-password-audit.ps1`](../code/collect-password-audit.ps1) | Исходный комплект | UTF-8 с BOM | `a3961916d8e9e607218cfeb13f203f3e0a79e832b4f3aeaa66850ca9872ba734` |
| [`PasswordAudit.Native.cs`](../code/PasswordAudit.Native.cs) | Исходный комплект | UTF-8 без BOM | `55bde9524a09c3e1daf224b31f7a6ccb0edfe24c9def119dc1d4202d6c2efd36` |
| [`collect-password-audit-xp.vbs`](../code/collect-password-audit-xp.vbs) | Исходный комплект | UTF-16 с BOM | `5a9867660b5cd0c83c36a27b235bf550c080e348b7a94b8eff88417b9ba65bbd` |
| [`deploy-windows.ps1`](../code/deploy-windows.ps1) | Исходный комплект | UTF-8 с BOM | `0eefa4852f42355c4f532d9fea704ff6a4170e91877e80915e763c015effa917` |
| [`install-task.ps1`](../code/install-task.ps1) | Исходный комплект | UTF-8 с BOM | `76433670184957ac7f707aa09dc69db4936e1661325cec43d3feb3e9c2227e03` |
| [`launch-setup.vbs`](../code/launch-setup.vbs) | Исходный комплект | UTF-16 с BOM | `c5dafbb71ff62527a502731f49f15dc48dcb687cee28f8672458e271741dc0be` |
| [`finish-xp-audit.vbs`](../code/finish-xp-audit.vbs) | Исходный комплект | UTF-16 с BOM | `09ae6ced4ac61593a31465f3169ad80dd38dbc14b536683d47bb66b62153d7b2` |
| [`deploy-xp.vbs`](../code/deploy-xp.vbs) | Исходный комплект | UTF-16 с BOM | `7e773fa80e14106ec73fbff6cb1b4c510d1666fc4239f91966525b42bce03a1c` |
| [`install-task-xp.cmd`](../code/install-task-xp.cmd) | Исходный комплект | OEM866 | `250f5c38f2d61febf90cf8510b25e86aab1b76e2a73a9376ff4230bfd3fca163` |
| [`wazuh-localfile.xml`](../code/wazuh-localfile.xml) | Исходный комплект | UTF-8 без BOM | `8ff6eea2b9370b30976906b843013b82a3ac04cf064abcdaf3887402bbb1e43f` |
| [`wazuh-group-agent.conf.example`](../code/wazuh-group-agent.conf.example) | Исходный комплект | UTF-8 без BOM | `0cee632f9f618609420b52e634f9b64c5be81db9a0e13e6402bbff1e93833529` |
| [`indexer-template.http`](../code/indexer-template.http) | Исходный комплект | UTF-8 без BOM | `937369d3ecfd05b5a135997ff3404b9d563c844a7603fb3371cd216fbd2a2174` |
| [`existing-index-mapping.json`](../code/existing-index-mapping.json) | Исходный комплект | UTF-8 без BOM | `6becb14b8d5a7c434681a5d356b2d0879824c61e74d2432df4e9435f03e1c4fa` |
| [`queries.http`](../code/queries.http) | Исходный комплект | UTF-8 без BOM | `f52caabc403fee9691d8da4194f1e5ea6d96710848e7cbe3f56e74ec682bd225` |
| [`server/materialize_password_state.py`](../code/server/materialize_password_state.py) | Исходный комплект | UTF-8 без BOM | `9464c77b20d37939a3f8a0960e42834a6738e4f74446dbedbeb24d289df8ca11` |
| [`server/config.example.json`](../code/server/config.example.json) | Исходный комплект | UTF-8 без BOM | `ad68b03ec1399e5240dddfa9f2418d372821c0bdee3c14fcaefa3def1395234d` |
| [`server/expected-agents.example.json`](../code/server/expected-agents.example.json) | Исходный комплект | UTF-8 без BOM | `8d7c3b652a747c9cf080d624b634aae68006591c638bb20289c86782621ef4e0` |
| [`server/indexer-auth.example.json`](../code/server/indexer-auth.example.json) | Исходный комплект | UTF-8 без BOM | `e7687e8e9d62b7493e257cf252a80bf947a33caa21697083e289f85b3192e236` |
| [`server/current-index-mapping.json`](../code/server/current-index-mapping.json) | Исходный комплект | UTF-8 без BOM | `ad47ef4d23b31387d7190be0100010716310ce214c85958f203f9c8f6c2e8264` |
| [`server/wazuh-password-audit-state.service`](../code/server/wazuh-password-audit-state.service) | Исходный комплект | UTF-8 без BOM | `16f65d2ee6c31b70c620c48bd6fa98387f7c51462f0dd598d2d3811a97f1d725` |
| [`server/wazuh-password-audit-state.timer`](../code/server/wazuh-password-audit-state.timer) | Исходный комплект | UTF-8 без BOM | `32ddc061ae61e15f0274f6ba41df3e6b54a625d459e52f50e2db84689d15fbaa` |
| [`dashboard/builder.py`](../code/dashboard/builder.py) | Исходный комплект | UTF-8 без BOM | `693f32ec82002be23fabf61d1c3bf13c3c3969979d916047c4b624fb37efd7d5` |
| [`dashboard/KPI.vega.json`](../code/dashboard/KPI.vega.json) | Исходный комплект | UTF-8 без BOM | `b7db1076c6b60d25245a2afc95c81c6254dd8f6ee6f07f51b4eabe5c4c860361` |
| [`dashboard/HOSTS.vega.json`](../code/dashboard/HOSTS.vega.json) | Исходный комплект | UTF-8 без BOM | `c1d074f970ea40522d642bbced24cfc51c5ffedcf69f5b48be4e5034f46a9069` |
| [`dashboard/USERS.vega.json`](../code/dashboard/USERS.vega.json) | Исходный комплект | UTF-8 без BOM | `3eae9dcf02a5562200b1bd993d3d1c2a0018f3c4fc6f149022a823be9b71b434` |
| [`dashboard/Wazuh-Password-Audit-v2.ndjson`](../code/dashboard/Wazuh-Password-Audit-v2.ndjson) | Исходный комплект | UTF-8 без BOM | `d9d609d542487755efc8dd35d6fd9372fadbedfa495dbd770e2158901a01b3fe` |
| [`dashboard/manifest.json`](../code/dashboard/manifest.json) | Исходный комплект | UTF-8 без BOM | `a0de0fd2e975b8d34b9e4e722078855507dc09d2d2820a820b7c81338ce30450` |
| [`verify-package.ps1`](../code/verify-package.ps1) | Исходный комплект | UTF-8 с BOM | `b237511233b23f2fdfdfa26e4c539a26d0e59fcacd4b592412f181eec89542e9` |
| [`server/test_materialize_password_state.py`](../code/server/test_materialize_password_state.py) | Исходный комплект | UTF-8 без BOM | `618da182d9f97636cba9992565e93631e1967ef949d7feef22b2ea1061f39b67` |
| [`dashboard/validate.cjs`](../code/dashboard/validate.cjs) | Исходный комплект | UTF-8 без BOM | `80142b430747c7abf58444328b2ad230d73e14f3f58167c4bc8df5231da02e11` |
| [`server/config.lab.json`](../code/server/config.lab.json) | Заполненный пример | UTF-8 без BOM | `8c999f08ad426c2f0c8fa946aa3b4ddc95d42e61871b648f0ab8fb70c2104a69` |
| [`server/expected-agents.lab.json`](../code/server/expected-agents.lab.json) | Заполненный пример | UTF-8 без BOM | `ea37b9db6d7627c1f633a643e7ce8b4966e2d6b173cc64e0891632072df91596` |
