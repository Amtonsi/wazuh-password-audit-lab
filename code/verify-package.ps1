# Проверяем пакет без чтения реальных пользователей, изменения ACL и создания задач.
# Проверочный стенд: Windows PowerShell 5.1. Сами сборщики рассчитаны также на PS2.
$ErrorActionPreference='Stop'
$packageRoot=Split-Path -Parent $MyInvocation.MyCommand.Path
$checks=New-Object Collections.ArrayList
function Assert([bool]$Condition,[string]$Name) {
    if (!$Condition) { throw ('FAIL: '+$Name) }; [void]$checks.Add($Name)
}
foreach ($name in @('collect-password-audit.ps1','install-task.ps1')) {
    $tokens=$null; $errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $packageRoot $name),[ref]$tokens,[ref]$errors)
    Assert ($errors.Count -eq 0) ('Parse '+$name)
}
. (Join-Path $packageRoot 'collect-password-audit.ps1') -SelfTest
Assert ($true) 'Collector pure self-test'
if (!('SiemPasswordAuditV2.Reader' -as [type])) { Add-Type -Path (Join-Path $packageRoot 'PasswordAudit.Native.cs') }
Assert ($true) 'Native helper compilation, without invoking NetAPI'
$nativeType=[SiemPasswordAuditV2.Reader].GetNestedType('USER_INFO_4',[Reflection.BindingFlags]::NonPublic)
if ([IntPtr]::Size -eq 8) { $expectedSize=192; $expectedSidOffset=152; $expectedExpiredOffset=184 }
else { $expectedSize=116; $expectedSidOffset=96; $expectedExpiredOffset=112 }
$sizeMethod=[Runtime.InteropServices.Marshal].GetMethod('SizeOf',[Type[]]@([Type]))
Assert ($sizeMethod.Invoke($null,@($nativeType)) -eq $expectedSize) 'Native USER_INFO_4 size'
Assert ([Runtime.InteropServices.Marshal]::OffsetOf($nativeType,'user_sid').ToInt32() -eq $expectedSidOffset) 'Native SID offset'
Assert ([Runtime.InteropServices.Marshal]::OffsetOf($nativeType,'password_expired').ToInt32() -eq $expectedExpiredOffset) 'Native expiry offset'

$user=@{Name='Тест "JSON"';Sid='S-1-5-21-1-2-3-1001';ReadError='';DetailKnown=$true;
    Flags=512;AgeSeconds=70*86400;ExpiredReported=$false;InternetIdentityKnown=$true;InternetIdentity=$false}
$policy=@{PolicyKnown=$true;MaxAgeUnlimited=$false;MaxAgeSeconds=90*86400}
$row=Get-UserAssessment $user $policy 60
Assert ($row.threshold_exceeded -and !$row.policy_expired_calculated) 'Organizational threshold differs from local expiry'
$policy.MaxAgeSeconds=30*86400; $user.AgeSeconds=45*86400
$row=Get-UserAssessment $user $policy 60
Assert (!$row.threshold_exceeded -and $row.policy_expired_calculated) 'Local expiry below organizational threshold'
$user.Flags=66048
Assert (!(Get-UserAssessment $user $policy 60).policy_expired_calculated) 'Never-expires suppresses calculated expiry'
$user.Flags=512; $policy.MaxAgeUnlimited=$true
Assert (!(Get-UserAssessment $user $policy 60).policy_expired_calculated) 'Unlimited policy is distinct from zero'
$policy.PolicyKnown=$false
Assert (!(Get-UserAssessment $user $policy 60).ContainsKey('policy_expired_calculated')) 'Unknown policy is not false'
$user.Sid=''
Assert ((Get-UserAssessment $user $policy 60).collection_status -eq 'partial') 'Missing SID is partial'
$user.Sid='S-1-5-21-1-2-3-1001'
$row=Get-UserAssessment $user $policy 60
$json=ConvertTo-AuditJson @{password_audit_v2=$row}
$decoded=$json | ConvertFrom-Json
Assert ($decoded.password_audit_v2.username -eq $user.Name) 'JSON round trip with Unicode and quotes'
Assert (($decoded.password_audit_v2.enabled -is [bool])) 'JSON boolean type'
Assert ($json -notmatch '[^\x00-\x7f]') 'JSON output contains ASCII only'

# Проверяем XML задачи через неперсистентный объект TaskDefinition, без RegisterTask.
$installer=[IO.File]::ReadAllText((Join-Path $packageRoot 'install-task.ps1'))
$xml=[regex]::Match($installer,'(?s)\$taskXml=@"\r?\n(.*?)\r?\n"@').Groups[1].Value
$xml=$xml.Replace('$start','2026-11-15T12:00:00').Replace('$commandXml','C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe').Replace('$argumentsXml','-NoProfile -File C:\SIEM-Audit\Password\collect-password-audit.ps1')
$service=New-Object -ComObject 'Schedule.Service'
$service.Connect(); $definition=$service.NewTask(0); $definition.XmlText=$xml
Assert ($definition.Triggers.Count -eq 2) 'Task XML schema: hourly and boot triggers'
$taskUser=$definition.Principal.UserId
if ($taskUser -like 'S-1-*') { $taskSid=$taskUser }
else { $taskSid=(New-Object Security.Principal.NTAccount($taskUser)).Translate([Security.Principal.SecurityIdentifier]).Value }
Assert ($taskSid -eq 'S-1-5-18') 'Task XML SYSTEM identity'
Assert ([int]$definition.Settings.MultipleInstances -eq 2) 'Task XML ignores overlapping runs'

& cscript.exe //Nologo (Join-Path $packageRoot 'collect-password-audit-xp.vbs') /selftest
Assert ($LASTEXITCODE -eq 0) 'XP collector pure self-test'
$result=@{passed=$true;checks=@($checks);test_runtime=$PSVersionTable.PSVersion.ToString();pointer_bits=([IntPtr]::Size*8);
    native_collection_executed=$false;tasks_registered=$false;acl_changed=$false;
    guest_operating_systems_tested=@();limitations='No Windows XP/7/10/11 guest integration test; no PowerShell 2 runtime test.'}
$result | ConvertTo-Json -Depth 5
