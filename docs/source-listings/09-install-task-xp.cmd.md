# `install-task-xp.cmd`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/install-task-xp.cmd). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Создаём первоначальную WazuhPasswordAudit на XP при её отсутствии и уже размещённом VBS-сборщике.

**Применение.** Запускаем CMD от администратора на подходящем новом XP-узле. Проверяем работающую службу Schedule.

**Особенности.** Использует старое имя WazuhPasswordAudit; при существующей задаче останавливается. Для текущей лаборатории с сохранением v1 выбираем finish-xp-audit.vbs и отдельное имя V2. CMD сохраняем в OEM866.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** OEM866. **Объём:** 36 строк.

**SHA256 оригинала:** `250f5c38f2d61febf90cf8510b25e86aab1b76e2a73a9376ff4230bfd3fca163`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```bat
@echo off
setlocal
REM Выполняем установку от имени локального администратора.
REM Сначала применяем ACL, затем создаём задачу с правами SYSTEM.
set "AUDIT_ROOT=C:\SIEM-Audit\Password"
set "AUDIT_SCRIPT=%AUDIT_ROOT%\collect-password-audit-xp.vbs"
set "AUDIT_CSCRIPT=%SystemRoot%\System32\cscript.exe"
set "AUDIT_SCHTASKS=%SystemRoot%\System32\schtasks.exe"
if not exist "%AUDIT_SCRIPT%" (
  echo Collector not found: %AUDIT_SCRIPT%
  exit /b 2
)
REM В Windows XP задачи хранятся в каталоге Tasks в файлах .job.
REM Существующую задачу не заменяем и не удаляем.
if exist "%SystemRoot%\Tasks\WazuhPasswordAudit.job" (
  echo Task WazuhPasswordAudit already exists. Review it before changing the schedule.
  exit /b 3
)
"%SystemRoot%\System32\sc.exe" query Schedule | "%SystemRoot%\System32\find.exe" "RUNNING" >nul
if errorlevel 1 (
  echo Task Scheduler is not running. Start the Schedule service before installation.
  exit /b 7
)
"%AUDIT_CSCRIPT%" //B //Nologo "%AUDIT_SCRIPT%" /secure
if errorlevel 1 (
  echo ACL configuration failed. No task was created.
  exit /b 4
)
REM Не применяем отсутствующий в Windows XP параметр замены /F.
REM Запускаем локальный сбор раз в час без сохранения пароля администратора.
"%AUDIT_SCHTASKS%" /Create /TN WazuhPasswordAudit /SC HOURLY /MO 1 /RU SYSTEM /TR "%AUDIT_CSCRIPT% //B //Nologo %AUDIT_SCRIPT% /threshold:60"
if errorlevel 1 exit /b 5
"%AUDIT_SCHTASKS%" /Run /TN WazuhPasswordAudit
if errorlevel 1 exit /b 6
echo Task created. Check the JSONL summary and Wazuh delivery.
exit /b 0
```
