#requires -version 2.0
<#
Устанавливаем сборщик Windows 7/10/11 в фиксированный каталог и создаём задачу SYSTEM.
Запускаем только от администратора. Существующую задачу не перезаписываем.
Подключение журнала к агенту Wazuh выполняем отдельно по инструкции.
#>
param([ValidateRange(1,3650)][int]$ThresholdDays=60)
$ErrorActionPreference='Stop'
$sourceDirectory=Split-Path -Parent $MyInvocation.MyCommand.Path
$destination='C:\SIEM-Audit\Password'
$taskName='WazuhPasswordAudit'
$administratorSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$systemSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an elevated Windows PowerShell session' }
if ([Environment]::OSVersion.Version -lt (New-Object Version(6,1))) { throw 'Windows 7 or later is required' }

$scheduler=New-Object -ComObject 'Schedule.Service'
$scheduler.Connect(); $taskFolder=$scheduler.GetFolder('\')
try { $existingTask=$taskFolder.GetTask($taskName) }
catch {
    $exception=$_.Exception
    while ($null -ne $exception.InnerException) { $exception=$exception.InnerException }
    if ([Runtime.InteropServices.Marshal]::GetHRForException($exception) -ne -2147024894) { throw }
    $existingTask=$null
}
if ($null -ne $existingTask) { throw 'WazuhPasswordAudit already exists. Review the existing task; it was not changed.' }

foreach ($name in @('collect-password-audit.ps1','PasswordAudit.Native.cs')) {
    if (!(Test-Path -LiteralPath (Join-Path $sourceDirectory $name) -PathType Leaf)) { throw ('Missing package file: ' + $name) }
}
function Protect-AuditPath([string]$Path,[bool]$Directory) {
    $item=Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('Reparse point is not allowed: ' + $Path) }
    # Удаляем наследованные разрешения. Оставляем запись/чтение только SYSTEM и Administrators.
    if ($Directory) { $acl=New-Object Security.AccessControl.DirectorySecurity }
    else { $acl=New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true,$false); $acl.SetOwner($administratorSid)
    foreach ($sid in @($administratorSid,$systemSid)) {
        if ($Directory) {
            $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl',
                'ContainerInherit, ObjectInherit','None','Allow')
        } else { $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow') }
        [void]$acl.AddAccessRule($rule)
    }
    # Буквальные .NET-пути совместимы с PowerShell 2.0; -LiteralPath у ACL-cmdlet добавлен в PS3.
    $item.SetAccessControl($acl)
    $item.Refresh();$check=$item.GetAccessControl()
    if ($check.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $administratorSid.Value -or
        !$check.AreAccessRulesProtected) { throw ('ACL/owner verification failed: ' + $Path) }
    $rules=$check.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
    if ($rules.Count -ne 2) { throw ('Unexpected ACL entries: ' + $Path) }
    foreach ($rule in $rules) {
        if (($rule.IdentityReference.Value -ne $administratorSid.Value -and $rule.IdentityReference.Value -ne $systemSid.Value) -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) { throw ('ACL rule verification failed: ' + $Path) }
    }
}
foreach ($directory in @('C:\SIEM-Audit',$destination,(Join-Path $destination 'logs'))) {
    if (!(Test-Path -LiteralPath $directory)) { [void][IO.Directory]::CreateDirectory($directory) }
    Protect-AuditPath $directory $true
}
# Проверяем и защищаем уже существующие файлы журналов, включая файл блокировки.
foreach ($item in @(Get-ChildItem -LiteralPath (Join-Path $destination 'logs') -Force)) {
    if ($item.PSIsContainer) { throw ('Unexpected directory in logs: ' + $item.FullName) }
    Protect-AuditPath $item.FullName $false
}
foreach ($name in @('collect-password-audit.ps1','PasswordAudit.Native.cs')) {
    $source=Join-Path $sourceDirectory $name; $target=Join-Path $destination $name
    if (Test-Path -LiteralPath $target) {
        if (((Get-Item -LiteralPath $target -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Target is a reparse point' }
    }
    if ([IO.Path]::GetFullPath($source) -ne [IO.Path]::GetFullPath($target)) {
        if (Test-Path -LiteralPath $target) { Copy-Item -LiteralPath $target -Destination ($target+'.before-'+[Guid]::NewGuid().ToString('N')+'.bak') }
        Copy-Item -LiteralPath $source -Destination $target -Force
    }
    Protect-AuditPath $target $false
}

# Явно выбираем 64-битный Windows PowerShell при запуске установщика из 32-битного процесса.
# В Task Scheduler используем настоящий System32: задача запускается уже вне WOW64-перенаправления.
$scheduledExecutable=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$destination+'\collect-password-audit.ps1" -ThresholdDays '+$ThresholdDays
$start=[DateTime]::Now.AddMinutes(1).ToString('yyyy-MM-ddTHH:mm:ss')
$commandXml=[Security.SecurityElement]::Escape($scheduledExecutable)
$argumentsXml=[Security.SecurityElement]::Escape($arguments)
$taskXml=@"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Read-only local SAM password metadata for Wazuh.</Description></RegistrationInfo>
  <Triggers>
    <TimeTrigger><Repetition><Interval>PT1H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>$start</StartBoundary><Enabled>true</Enabled><RandomDelay>PT10M</RandomDelay></TimeTrigger>
    <BootTrigger><Enabled>true</Enabled><Delay>PT5M</Delay></BootTrigger>
  </Triggers>
  <Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><Enabled>true</Enabled><ExecutionTimeLimit>PT10M</ExecutionTimeLimit></Settings>
  <Actions Context="System"><Exec><Command>$commandXml</Command><Arguments>$argumentsXml</Arguments></Exec></Actions>
</Task>
"@
# TASK_CREATE=2; TASK_LOGON_SERVICE_ACCOUNT=5. Existing task creation must fail.
$registered=$taskFolder.RegisterTask($taskName,$taskXml,2,'S-1-5-18',$null,5,$null)
[void]$registered.Run($null)
Write-Output 'Task created and first run requested. Verify summary and delivery in Wazuh.'
