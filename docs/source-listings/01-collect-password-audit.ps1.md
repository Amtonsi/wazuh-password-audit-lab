# `collect-password-audit.ps1`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/collect-password-audit.ps1). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Получаем и оцениваем метаданные локальных пользователей Windows 7/10/11. Записываем пользовательские строки и завершающую сводку JSONL.

**Применение.** Размещаем рядом PasswordAudit.Native.cs. Контроль: powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SIEM-Audit\Password\collect-password-audit.ps1 -ThresholdDays 60. Самопроверка: добавляем -SelfTest.

**Особенности.** Содержимое и хеши паролей не извлекаем. Неизвестные свойства не подменяем false; облачный пароль исключаем из оценки. Файл PS1 сохраняем в UTF-8 с BOM для старого Windows PowerShell.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-8 с BOM. **Объём:** 168 строк.

**SHA256 оригинала:** `a3961916d8e9e607218cfeb13f203f3e0a79e832b4f3aeaa66850ca9872ba734`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```powershell
#requires -version 2.0
<#
Собираем метаданные локальных учётных записей на Windows 7/10/11.
Читаем SAM через Windows API; AD, пароли и хеши не запрашиваем.
Не изменяем парольную политику и учётные записи.
Для PowerShell 2.0 сохраняем этот файл в UTF-8 с BOM.
#>
param(
    [ValidateRange(1,3650)][int]$ThresholdDays = 60,
    [string]$OutputDirectory = 'C:\SIEM-Audit\Password\logs',
    [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

function ConvertTo-AuditJson($Value) {
    # Формируем ASCII JSON: русские символы кодируем как \uXXXX.
    # Не используем ConvertTo-Json, отсутствующий в PowerShell 2.0.
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' }; return 'false' }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = @(); foreach ($key in @($Value.Keys | Sort-Object)) {
            $parts += (ConvertTo-AuditJson ([string]$key)) + ':' + (ConvertTo-AuditJson $Value[$key])
        }; return '{' + ($parts -join ',') + '}'
    }
    if (($Value -is [System.Collections.IEnumerable]) -and !($Value -is [string])) {
        $parts = @(); foreach ($entry in $Value) { $parts += ConvertTo-AuditJson $entry }
        return '[' + ($parts -join ',') + ']'
    }
    if (($Value -is [ValueType]) -and !($Value -is [char])) {
        return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('"')
    foreach ($character in ([string]$Value).ToCharArray()) {
        $code = [int]$character
        if ($code -eq 34 -or $code -eq 92) { [void]$builder.Append('\'); [void]$builder.Append($character) }
        elseif ($code -lt 32 -or $code -gt 126) { [void]$builder.Append(('\u{0:x4}' -f $code)) }
        else { [void]$builder.Append($character) }
    }
    [void]$builder.Append('"'); return $builder.ToString()
}
function Get-UserAssessment($User, $Policy, [int]$Days) {
    $row = @{ username=$User.Name; read_error=$User.ReadError; collection_status='partial' }
    if ($User.Sid) { $row.sid = $User.Sid }
    if (!$User.DetailKnown) { return $row }
    $row.enabled = ($User.Flags -band 2) -eq 0
    $row.never_expires = ($User.Flags -band 65536) -ne 0
    $row.expired_reported = [bool]$User.ExpiredReported
    $row.age_seconds = [long]$User.AgeSeconds
    $row.age_days = [Math]::Floor([double]$User.AgeSeconds / 86400)
    if (!$User.InternetIdentityKnown) { return $row }
    $row.internet_identity = [bool]$User.InternetIdentity
    if ($User.InternetIdentity) {
        if ($User.Sid) { $row.collection_status='excluded' }
        $row.exclusion_reason='cloud_password_not_assessed'
        return $row
    }
    # Сравниваем секунды: ровно 60 суток не превышают порог; 60 суток + 1 секунда превышают.
    $row.threshold_exceeded = [double]$User.AgeSeconds -gt ([double]$Days * 86400)
    if ($Policy.PolicyKnown) {
        $row.policy_expired_calculated = (!$row.never_expires -and !$Policy.MaxAgeUnlimited -and
            ([double]$User.AgeSeconds -ge [double]$Policy.MaxAgeSeconds))
    }
    if ($User.Sid) { $row.collection_status='ok' }; return $row
}
if ($SelfTest) {
    # Проверяем расчёты на искусственных данных. К SAM, файлам и Планировщику не обращаемся.
    $user=@{Name='Тест';Sid='S-1-5-21-1-2-3-1001';ReadError='';DetailKnown=$true;
        Flags=512;AgeSeconds=5184000;ExpiredReported=$false;InternetIdentityKnown=$true;InternetIdentity=$false}
    $policy=@{PolicyKnown=$true;MaxAgeUnlimited=$false;MaxAgeSeconds=7776000}
    if ((Get-UserAssessment $user $policy 60).threshold_exceeded) { throw 'Exact threshold failed' }
    $user.AgeSeconds++; if (!(Get-UserAssessment $user $policy 60).threshold_exceeded) { throw 'Threshold + 1 failed' }
    $user.AgeSeconds=0; if ((Get-UserAssessment $user $policy 60).age_seconds -ne 0) { throw 'Zero age failed' }
    $user.Flags=66048; if (!(Get-UserAssessment $user $policy 60).never_expires) { throw 'Never expires failed' }
    $user.InternetIdentity=$true
    if ((Get-UserAssessment $user $policy 60).ContainsKey('threshold_exceeded')) { throw 'Cloud scope failed' }
    $user.DetailKnown=$false
    if ((Get-UserAssessment $user $policy 60).ContainsKey('age_seconds')) { throw 'Unknown converted to zero' }
    if ((ConvertTo-AuditJson 'Ж') -ne '"\u0416"') { throw 'Unicode JSON failed' }
    Write-Output 'Self-test: PASS (threshold, zero age, flags, cloud scope, unknown, JSON)'; return
}

$runId=[Guid]::NewGuid().ToString('D')
$observed=[DateTime]::UtcNow
$base=@{schema_version=2;collector_version='2.0.0';computer=$env:COMPUTERNAME;
    run_id=$runId;observed_at_utc=$observed.ToString('yyyy-MM-ddTHH:mm:ss.fffZ');
    threshold_days=$ThresholdDays;scope='local_sam_metadata'}
function New-AuditRecord([string]$Kind) {
    $record=@{}; foreach ($key in $base.Keys) { $record[$key]=$base[$key] }
    $record.kind=$Kind; return $record
}
function Write-AuditRecord($Record) {
    $writer.WriteLine((ConvertTo-AuditJson @{password_audit_v2=$Record})); $writer.Flush()
}
$lockStream=$null; $writer=$null; $exitCode=0
try {
    [void][IO.Directory]::CreateDirectory($OutputDirectory)
    # Блокировка снимается ОС при завершении процесса, в том числе аварийном.
    $lockStream=[IO.File]::Open((Join-Path $OutputDirectory 'collector.lock'),
        [IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $path=Join-Path $OutputDirectory ('password-audit-' + $observed.ToString('yyyyMMdd') + '.jsonl')
    $fileStream=[IO.File]::Open($path,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    $writer=New-Object IO.StreamWriter($fileStream, [Text.Encoding]::ASCII)
    $summary=New-AuditRecord 'summary'
    $emitted=0
    try {
        # Не допускаем запуска на контроллере домена: область сбора ограничена локальным SAM АРМ.
        $product=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType
        if ($product -ne 'WinNT') { throw 'Only Windows workstation local SAM is in scope' }
        if ([Environment]::OSVersion.Version -lt (New-Object Version(6,1))) { throw 'Windows 7 or later is required' }
        if (!('SiemPasswordAuditV2.Reader' -as [type])) { Add-Type -Path (Join-Path $scriptDirectory 'PasswordAudit.Native.cs') }
        $snapshot=[SiemPasswordAuditV2.Reader]::Read()
        $unknown=0; $knownOver=0; $enabled=0; $emitted=0; $excluded=0
        foreach ($user in $snapshot.Users) {
            $record=New-AuditRecord 'user'
            $assessment=Get-UserAssessment $user $snapshot $ThresholdDays
            foreach ($key in $assessment.Keys) { $record[$key]=$assessment[$key] }
            if ($assessment.collection_status -eq 'partial') { $unknown++ }
            if ($assessment.collection_status -eq 'excluded') { $excluded++ }
            if ($assessment.ContainsKey('enabled') -and $assessment.enabled) {
                $enabled++; if ($assessment.ContainsKey('threshold_exceeded') -and $assessment.threshold_exceeded) { $knownOver++ }
            }
            Write-AuditRecord $record; $emitted++
        }
        $summary.enumeration_complete=$snapshot.EnumerationComplete
        $summary.identity_complete=$snapshot.IdentityComplete
        # expected_count фиксируем только после полного перечисления; при ошибке не выдаём частичный размер за полный.
        if ($snapshot.EnumerationComplete) { $summary.expected_user_count=$snapshot.Users.Count }
        $summary.emitted_user_count=$emitted; $summary.known_enabled_count=$enabled
        if ($unknown -eq 0 -and $snapshot.EnumerationComplete) { $summary.enabled_count=$enabled }
        $summary.unknown_count=$unknown; $summary.excluded_count=$excluded
        $summary.known_over_threshold_count=$knownOver
        $summary.collection_status='ok'
        if (!$snapshot.EnumerationComplete) { $summary.collection_status='error' }
        elseif (!$snapshot.IdentityComplete -or $unknown -gt 0 -or !$snapshot.PolicyKnown) { $summary.collection_status='partial' }
        $summary.enumeration_error=$snapshot.EnumerationError
        $summary.policy_read_status='unknown'
        if ($snapshot.PolicyKnown) {
            $summary.policy_read_status='ok'; $summary.policy_max_age_unlimited=$snapshot.MaxAgeUnlimited
            if (!$snapshot.MaxAgeUnlimited) { $summary.policy_max_age_seconds=[long]$snapshot.MaxAgeSeconds }
            $summary.policy_min_age_seconds=[long]$snapshot.MinAgeSeconds
            $summary.policy_min_length=[long]$snapshot.MinLength
            $summary.policy_history_length=[long]$snapshot.HistoryLength
        } else { $summary.policy_read_error=$snapshot.PolicyError }
        if ($snapshot.EnumerationComplete -and $snapshot.IdentityComplete -and $unknown -eq 0) {
            # Итог относится к локальным SAM-паролям; облачные аккаунты перечисляем отдельно как excluded.
            $summary.over_threshold_count=$knownOver
        }
    } catch {
        $summary.collection_status='error'; $summary.enumeration_complete=$false
        $summary.identity_complete=$false; $summary.error=$_.Exception.Message; $exitCode=1
        $summary.emitted_user_count=$emitted
    }
    # Завершающая запись связывает строки пользователей в один проверяемый снимок.
    $summary.completed_at_utc=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    Write-AuditRecord $summary
    if ($summary.collection_status -ne 'ok') { $exitCode=1 }
    Write-Output ('Snapshot: ' + $path + '; run_id=' + $runId + '; status=' + $summary.collection_status)
} catch {
    # Если недоступен сам журнал, сообщение остаётся в stderr/результате задачи;
    # на стороне SIEM отсутствие свежего снимка должно давать состояние «Нет данных».
    [Console]::Error.WriteLine($_.Exception.Message); $exitCode=2
} finally {
    if ($null -ne $writer) { $writer.Dispose() }
    if ($null -ne $lockStream) { $lockStream.Dispose() }
}
exit $exitCode
```
