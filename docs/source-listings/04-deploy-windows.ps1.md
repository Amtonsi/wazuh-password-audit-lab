# `deploy-windows.ps1`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/deploy-windows.ps1). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Комплексно развёртываем Wazuh Agent и сборщик Windows 7/10/11, добавляем источник JSONL, защищаем каталог и создаём задачу SYSTEM.

**Применение.** Для нового АРМ выполняем от администратора: powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Install\windows-password-audit-v2\deploy-windows.ps1 -Manager 192.168.179.20 -ThresholdDays 60. Рядом размещаем согласованный MSI и индивидуальный agent-client.keys.

**Особенности.** Существующие ключ и задачу по умолчанию сохраняем. Перед заменой конфигурации создаём backup; после старта ожидаем источник и соединение. При остановке агента восстанавливаем конфиг. На уже работающем стенде повторную установку не выполняем как проверку.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-8 с BOM. **Объём:** 447 строк.

**SHA256 оригинала:** `0eefa4852f42355c4f532d9fea704ff6a4170e91877e80915e763c015effa917`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```powershell
#requires -version 2.0
<#
Развёртываем агент и сборщик на Windows 7/10/11 из подготовленной локальной или HGFS-папки.
Запускаем от администратора. Пароли и парольные политики не изменяем.
Существующие ключи и задачу сохраняем, если явно не указаны флаги замены.
Результат без секретов записываем рядом с исходным скриптом в deploy-result.json.
#>
param(
    [ValidateRange(1,3650)][int]$ThresholdDays=60,
    [string]$Manager='192.168.179.20',
    [switch]$ReplaceAgentKey,
    [switch]$ReplaceTask
)
$ErrorActionPreference='Stop'
$sourceDirectory=Split-Path -Parent $MyInvocation.MyCommand.Path
$runId=[Guid]::NewGuid().ToString('N')
$deploymentStartedUtc=[DateTime]::UtcNow
$computerName=$env:COMPUTERNAME;if(!$computerName){$computerName=[Environment]::MachineName}
$result=@{status='started';run_id=$runId;computer=$computerName;
    started_at_utc=$deploymentStartedUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ');
    steps=(New-Object Collections.ArrayList);backups=(New-Object Collections.ArrayList)}
$taskName='WazuhPasswordAudit'
$staging=$null; $agentDirectory=$null; $configBackup=$null; $keyBackup=$null; $earlyReportPath=$null
$configChanged=$false; $keyChanged=$false; $serviceStopped=$false; $agentStartAttempted=$false

function Add-Step([string]$Text) { [void]$result.steps.Add($Text); Write-Output $Text }
function ConvertTo-DeployJson($Value) {
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if($Value){return 'true'};return 'false' }
    if ($Value -is [Collections.IDictionary]) {
        $parts=@(); foreach($key in @($Value.Keys|Sort-Object)) {
            $parts+=(ConvertTo-DeployJson ([string]$key))+':'+(ConvertTo-DeployJson $Value[$key])
        };return '{'+($parts -join ',')+'}'
    }
    if (($Value -is [Collections.IEnumerable]) -and !($Value -is [string])) {
        $parts=@();foreach($item in $Value){$parts+=ConvertTo-DeployJson $item};return '['+($parts -join ',')+']'
    }
    if (($Value -is [ValueType]) -and !($Value -is [char])) {
        return [Convert]::ToString($Value,[Globalization.CultureInfo]::InvariantCulture)
    }
    $builder=New-Object Text.StringBuilder;[void]$builder.Append('"')
    foreach($character in ([string]$Value).ToCharArray()) {
        $code=[int]$character
        if($code -eq 34 -or $code -eq 92){[void]$builder.Append('\');[void]$builder.Append($character)}
        elseif($code -lt 32 -or $code -gt 126){[void]$builder.Append(('\u{0:x4}' -f $code))}
        else{[void]$builder.Append($character)}
    };[void]$builder.Append('"');return $builder.ToString()
}
function Protect-DeployPath([string]$Path,[bool]$Directory) {
    $item=Get-Item -LiteralPath $Path -Force
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Reparse point rejected: '+$Path)}
    $admin=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    if($Directory){$acl=New-Object Security.AccessControl.DirectorySecurity}
    else{$acl=New-Object Security.AccessControl.FileSecurity}
    $acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($admin)
    foreach($sid in @($admin,$system)) {
        if($Directory){$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit, ObjectInherit','None','Allow')}
        else{$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')}
        [void]$acl.AddAccessRule($rule)
    }
    # Get/Set-Acl -LiteralPath появились только в PowerShell 3.0.
    # FileInfo/DirectoryInfo используют буквальный путь и API .NET 2.0.
    $item.SetAccessControl($acl)
    $item.Refresh();$check=$item.GetAccessControl()
    if(!$check.AreAccessRulesProtected -or $check.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $admin.Value){throw ('Private ACL verification failed: '+$Path)}
}
function Get-AgentDirectory {
    $service=Get-WmiObject Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction SilentlyContinue
    if($null -ne $service) {
        $binary=$null
        if($service.PathName -match '^\s*"([^"]+\.exe)"'){$binary=$matches[1]}
        elseif($service.PathName -match '^\s*(.+?\.exe)(?:\s|$)'){$binary=$matches[1]}
        if($binary -and (Test-Path -LiteralPath $binary -PathType Leaf)){return (Split-Path -Parent $binary)}
    }
    $candidates=@()
    if(${env:ProgramFiles(x86)}){$candidates+=(Join-Path ${env:ProgramFiles(x86)} 'ossec-agent')}
    $candidates+=(Join-Path $env:ProgramFiles 'ossec-agent')
    foreach($candidate in $candidates){if(Test-Path -LiteralPath (Join-Path $candidate 'ossec.conf')){return $candidate}}
    throw 'Cannot locate the Wazuh service installation directory'
}
function Read-KeyRecord([string]$Path) {
    if(!(Test-Path -LiteralPath $Path -PathType Leaf)){return $null}
    $text=[IO.File]::ReadAllText($Path)
    if([string]::IsNullOrEmpty($text.Trim())){return $null}
    $lines=@($text -split '\r?\n' | Where-Object {$_.Trim() -and !$_.Trim().StartsWith('#')})
    if($lines.Count -ne 1){throw 'Expected exactly one non-comment agent key record; inspect the key file manually'}
    $parts=[regex]::Split($lines[0].Trim(),'\s+')
    if($parts.Count -ne 4 -or $parts[0] -notmatch '^\d+$' -or $parts[0] -eq '000' -or $parts[3] -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'Agent key record format is invalid; expected a native four-field client.keys line'
    }
    return @{Text=($parts -join ' ');Id=$parts[0];Name=$parts[1];Address=$parts[2]}
}
function Save-Backup([string]$Path,[string]$Name) {
    if(!(Test-Path -LiteralPath $Path -PathType Leaf)){return $null}
    $target=Join-Path $staging $Name
    Copy-Item -LiteralPath $Path -Destination $target
    Protect-DeployPath $target $false
    [void]$result.backups.Add($target)
    return $target
}
function Invoke-Waited([string]$Executable,[string]$Arguments) {
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$Executable;$start.Arguments=$Arguments
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $process=[Diagnostics.Process]::Start($start)
    $process.WaitForExit();$code=$process.ExitCode;$process.Dispose();return $code
}
function Get-ExistingTask($Folder) {
    try{return $Folder.GetTask($taskName)}
    catch{
        $exception=$_.Exception;while($null -ne $exception.InnerException){$exception=$exception.InnerException}
        if([Runtime.InteropServices.Marshal]::GetHRForException($exception) -ne -2147024894){throw}
        return $null
    }
}
function New-AgentLogCursor([string]$Path) {
    # Отсекаем все сообщения до Start-Service. Ротацию/усечение учитываем отдельно.
    $cursor=@{Offset=[long]0;CreationTicks=[long]0;Pending=''}
    if(Test-Path -LiteralPath $Path -PathType Leaf) {
        $item=Get-Item -LiteralPath $Path
        $cursor.Offset=[long]$item.Length;$cursor.CreationTicks=$item.CreationTimeUtc.Ticks
    }
    return $cursor
}
function Read-NewAgentLogLines([string]$Path,$Cursor) {
    if(!(Test-Path -LiteralPath $Path -PathType Leaf)){return @()}
    $item=Get-Item -LiteralPath $Path
    if(($Cursor.CreationTicks -ne 0 -and $item.CreationTimeUtc.Ticks -ne $Cursor.CreationTicks) -or $item.Length -lt $Cursor.Offset) {
        $Cursor.Offset=[long]0;$Cursor.Pending=''
    }
    $Cursor.CreationTicks=$item.CreationTimeUtc.Ticks
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        [void]$stream.Seek($Cursor.Offset,[IO.SeekOrigin]::Begin)
        $available=[long]$stream.Length-$stream.Position
        if($available -le 0){return @()}
        $count=[int][Math]::Min($available,1048576)
        $bytes=New-Object byte[] $count
        $read=$stream.Read($bytes,0,$count)
        $Cursor.Offset=$stream.Position
        # Проверяем ASCII-маркеры и путь; локализованные части не участвуют в сопоставлении.
        $text=$Cursor.Pending+[Text.Encoding]::UTF8.GetString($bytes,0,$read)
        $lastNewline=$text.LastIndexOf("`n")
        if($lastNewline -lt 0){$Cursor.Pending=$text;return @()}
        $Cursor.Pending=$text.Substring($lastNewline+1)
        return @($text.Substring(0,$lastNewline) -split '\r?\n')
    } finally {$stream.Dispose()}
}
function Test-PasswordSourceAnalyzed([string]$Line) {
    if($Line -notmatch '(?i)\bAnalyzing\s+file\b'){return $false}
    $normalized=$Line.Replace('/','\')
    $prefix=[regex]::Escape('C:\SIEM-Audit\Password\logs\password-audit-')
    return $normalized -match ($prefix+'[^''"\r\n]*\.jsonl')
}
function Test-ManagerConnectedLine([string]$Line) {
    return ($Line -match '(?i)\bConnected\b' -and $Line -notmatch '(?i)\b(?:not|never)\s+connected\b|\bdisconnected\b|\bfailed\b')
}
function Get-AgentServiceDecision([string]$ServiceStatus,[string]$ReadinessStatus) {
    # Чистая оценка состояния: остановка службы требует ошибки/восстановления,
    # отсутствие связи при работающей службе означает только неполное подтверждение.
    if($ServiceStatus -ne 'Running'){return @{result='error';rollback_required=$true}}
    if($ReadinessStatus -eq 'ready'){return @{result='ready';rollback_required=$false}}
    return @{result='partial';rollback_required=$false}
}
function Wait-AgentPasswordReadiness([string]$LogPath,[string]$StatePath,$Cursor,[DateTime]$StartedUtc) {
    $readiness=@{logcollector_source_ready=$false;manager_connected=$false;readiness_timeout_seconds=60;readiness_status='timeout'}
    $deadline=[DateTime]::UtcNow.AddSeconds(60)
    do {
        try {
            foreach($line in @(Read-NewAgentLogLines $LogPath $Cursor)) {
                if(Test-PasswordSourceAnalyzed $line){$readiness.logcollector_source_ready=$true}
                if(Test-ManagerConnectedLine $line){$readiness.manager_connected=$true}
            }
            # Старый connected-state до перезапуска не принимаем за подтверждение нового соединения.
            if(Test-Path -LiteralPath $StatePath -PathType Leaf) {
                $state=Get-Item -LiteralPath $StatePath
                if($state.LastWriteTimeUtc -ge $StartedUtc -and $state.LastWriteTimeUtc.Ticks -ne $Cursor.StateWriteTicks) {
                    $stateText=[IO.File]::ReadAllText($StatePath)
                    if($stateText -match '(?im)^\s*status\s*=\s*[''"]?connected[''"]?\s*$'){$readiness.manager_connected=$true}
                }
            }
        } catch {$readiness.readiness_read_error=$_.Exception.Message}
        if($readiness.logcollector_source_ready -and $readiness.manager_connected) {
            $readiness.readiness_status='ready'
            $readiness.readiness_confirmed_at_utc=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            return $readiness
        }
        $remainingMs=($deadline-[DateTime]::UtcNow).TotalMilliseconds
        if($remainingMs -gt 0){Start-Sleep -Milliseconds ([int][Math]::Min(2000,$remainingMs))}
    } while([DateTime]::UtcNow -lt $deadline)
    $readiness.readiness_warning='No new confirmation of both password JSONL subscription and manager connection within 60 seconds. The hourly task remains installed; verify ossec.log and indexed delivery. No rollback was requested for this readiness timeout.'
    return $readiness
}

try {
    # Ранний результат существует до MSI/защиты ProgramData, в том числе для PS2-ошибок.
    $earlyDirectory=Join-Path ([IO.Path]::GetTempPath()) ('SIEM-Wazuh-Bootstrap-'+$runId)
    [void][IO.Directory]::CreateDirectory($earlyDirectory)
    $earlyReportPath=Join-Path $earlyDirectory 'deploy-result.json'
    $result.fallback_report_path=$earlyReportPath
    $result.powershell_version=$PSVersionTable.PSVersion.ToString()
    [IO.File]::WriteAllText($earlyReportPath,(ConvertTo-DeployJson $result),(New-Object Text.UTF8Encoding($false)))
    Write-Output ('Bootstrap report: '+$earlyReportPath)
    $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator elevation is required'}
    Protect-DeployPath $earlyDirectory $true;Protect-DeployPath $earlyReportPath $false
    if([Environment]::OSVersion.Version -lt (New-Object Version(6,1))){throw 'Use the separate XP installation procedure for Windows XP'}
    if($Manager -notmatch '^\d{1,3}(\.\d{1,3}){3}$'){throw 'Manager must be a literal IPv4 address'}
    foreach($name in @('collect-password-audit.ps1','PasswordAudit.Native.cs','install-task.ps1')) {
        if(!(Test-Path -LiteralPath (Join-Path $sourceDirectory $name) -PathType Leaf)){throw ('Missing package file: '+$name)}
    }
    $programData=$env:ProgramData
    if(!$programData){$programData=Join-Path $env:SystemDrive 'ProgramData'}
    $stagingParent=Join-Path $programData 'SIEM-Wazuh-Deploy'
    if(!(Test-Path -LiteralPath $stagingParent)){[void][IO.Directory]::CreateDirectory($stagingParent)}
    Protect-DeployPath $stagingParent $true
    $staging=Join-Path $stagingParent $runId
    [void][IO.Directory]::CreateDirectory($staging);Protect-DeployPath $staging $true
    $result.staging_directory=$staging
    foreach($name in @('collect-password-audit.ps1','PasswordAudit.Native.cs','install-task.ps1')) {
        Copy-Item -LiteralPath (Join-Path $sourceDirectory $name) -Destination (Join-Path $staging $name)
        Protect-DeployPath (Join-Path $staging $name) $false
    }
    $service=Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
    $agentWasPresent=$null -ne $service;$result.agent_was_present=$agentWasPresent
    if(!$agentWasPresent) {
        $msiSource=Join-Path $sourceDirectory 'wazuh-agent-4.14.9-1.msi'
        if(!(Test-Path -LiteralPath $msiSource -PathType Leaf)){throw 'Wazuh MSI is missing from the package'}
        $msiLocal=Join-Path $staging 'wazuh-agent-4.14.9-1.msi'
        Copy-Item -LiteralPath $msiSource -Destination $msiLocal
        Add-Step 'Installing Wazuh Agent 4.14.9; no automatic restart requested'
        $msiLog=Join-Path $staging 'wazuh-install.log'
        $msiCode=Invoke-Waited (Join-Path $env:SystemRoot 'System32\msiexec.exe') ('/i "'+$msiLocal+'" /qn /norestart /l*v "'+$msiLog+'"')
        $result.msi_exit_code=$msiCode;$result.reboot_required=$msiCode -eq 3010
        if($msiCode -ne 0 -and $msiCode -ne 3010){throw ('MSI installation failed with exit code '+$msiCode)}
        if($null -eq (Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue)){throw 'WazuhSvc did not appear after MSI installation'}
    } else {Add-Step 'Existing Wazuh installation preserved'}
    $agentDirectory=Get-AgentDirectory;$result.agent_directory=$agentDirectory
    $configPath=Join-Path $agentDirectory 'ossec.conf';$keyPath=Join-Path $agentDirectory 'client.keys'
    if(!(Test-Path -LiteralPath $configPath)){throw 'Installed ossec.conf is missing'}
    $configBackup=Save-Backup $configPath 'ossec.conf.before-deploy'
    $keyBackup=Save-Backup $keyPath 'client.keys.before-deploy'

    $existingKey=Read-KeyRecord $keyPath
    $newKey=$null
    if($null -eq $existingKey -or $ReplaceAgentKey) {
        $newKey=Read-KeyRecord (Join-Path $sourceDirectory 'agent-client.keys')
        if($null -eq $newKey){throw 'No native agent key was supplied for enrollment'}
    }
    if($null -ne $existingKey -and !$ReplaceAgentKey) {
        $result.key_status='existing_preserved';$result.agent_id=$existingKey.Id;$result.agent_name=$existingKey.Name
    } else {
        $result.key_status='imported';if($null -ne $existingKey){$result.key_status='replaced_explicitly'}
        $result.agent_id=$newKey.Id;$result.agent_name=$newKey.Name
    }

    $passwordLocation='C:\SIEM-Audit\Password\logs\password-audit-*.jsonl'
    $document=New-Object Xml.XmlDocument;$document.PreserveWhitespace=$true
    if($agentWasPresent) {
        # В существующей конфигурации не меняем client, журналы, FIM и другие модули.
        # Несколько ossec_config-корней требуют отдельной проверки: не переписываем такой файл.
        $document.Load($configPath)
        if($document.DocumentElement.Name -ne 'ossec_config'){throw 'Unexpected ossec.conf root element'}
        $existingSource=@($document.DocumentElement.SelectNodes('localfile')|Where-Object {$_.location -eq $passwordLocation})
        if($existingSource.Count -gt 0) {
            foreach($entry in $existingSource){if($entry.log_format -ne 'json'){throw 'The existing password audit source has a non-JSON format'}}
            $result.config_status='existing_source_preserved'
        } else {
            $localfile=$document.CreateElement('localfile')
            foreach($pair in @(@('location',$passwordLocation),@('log_format','json'))) {
                $node=$document.CreateElement($pair[0]);$node.InnerText=$pair[1];[void]$localfile.AppendChild($node)
            }
            [void]$document.DocumentElement.AppendChild($localfile)
            $result.config_status='password_source_appended'
        }
    } else {
        # Для новой установки задаём подключение, базовые журналы, FIM и JSON-аудит.
        $document.LoadXml('<ossec_config><client><server><address>'+$Manager+'</address><port>1514</port><protocol>tcp</protocol></server><enrollment><enabled>no</enabled></enrollment></client><localfile><location>Application</location><log_format>eventchannel</log_format></localfile><localfile><location>System</location><log_format>eventchannel</log_format></localfile><localfile><location>Security</location><log_format>eventchannel</log_format></localfile><syscheck><disabled>no</disabled><frequency>300</frequency><scan_on_start>yes</scan_on_start><directories check_all="yes" realtime="yes">C:\SIEM-Lab</directories></syscheck><localfile><location>'+$passwordLocation+'</location><log_format>json</log_format></localfile></ossec_config>')
        $result.config_status='new_install_configured'
    }

    if((Get-Service WazuhSvc).Status -ne 'Stopped'){Stop-Service WazuhSvc -Force;$serviceStopped=$true}
    if($newKey) {
        [IO.File]::WriteAllText($keyPath,$newKey.Text+[Environment]::NewLine,[Text.Encoding]::ASCII)
        Protect-DeployPath $keyPath $false;$keyChanged=$true
    }
    if($result.config_status -ne 'existing_source_preserved') {
        $temporary=Join-Path $agentDirectory ('ossec.conf.'+$runId+'.tmp')
        $settings=New-Object Xml.XmlWriterSettings;$settings.Encoding=New-Object Text.UTF8Encoding($false)
        $settings.Indent=$true
        # Нативный парсер Wazuh ожидает конфигурацию без XML-пролога.
        $settings.OmitXmlDeclaration=$true
        $xmlWriter=[Xml.XmlWriter]::Create($temporary,$settings)
        try{$document.Save($xmlWriter)}finally{$xmlWriter.Close()}
        [IO.File]::Copy($temporary,$configPath,$true);$configChanged=$true
        Remove-Item -LiteralPath $temporary
    }
    if(!$agentWasPresent) {
        if(!(Test-Path -LiteralPath 'C:\SIEM-Lab')){[void][IO.Directory]::CreateDirectory('C:\SIEM-Lab')}
        if(!(Test-Path -LiteralPath 'C:\SIEM-Lab\deployment-baseline.txt')) {
            [IO.File]::WriteAllText('C:\SIEM-Lab\deployment-baseline.txt','SIEM deployment baseline',[Text.Encoding]::ASCII)
        }
    }
    $scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect();$taskFolder=$scheduler.GetFolder('\')
    $existingTask=Get-ExistingTask $taskFolder
    if($null -ne $existingTask -and !$ReplaceTask) {
        $result.task_status='existing_preserved';Add-Step 'Existing password audit task preserved; review its script and schema'
    } else {
        if($null -ne $existingTask) {
            $taskBackup=Join-Path $staging 'WazuhPasswordAudit.before.xml'
            [IO.File]::WriteAllText($taskBackup,$existingTask.Xml,(New-Object Text.UnicodeEncoding($false,$true)))
            Protect-DeployPath $taskBackup $false;[void]$result.backups.Add($taskBackup)
            if($existingTask.State -eq 4){throw 'Existing password audit task is running; wait before explicit replacement'}
            $taskFolder.DeleteTask($taskName,0)
        }
        $powerShell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $setupCode=Invoke-Waited $powerShell ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $staging 'install-task.ps1')+'" -ThresholdDays '+$ThresholdDays)
        $result.collector_setup_exit_code=$setupCode
        if($setupCode -ne 0){throw ('Collector task installation failed with exit code '+$setupCode)}
        $result.task_status='created';Add-Step 'Password audit task installed and first run requested'
    }
    $agentLogPath=Join-Path $agentDirectory 'ossec.log'
    $agentStatePath=Join-Path $agentDirectory 'wazuh-agent.state'
    $agentLogCursor=New-AgentLogCursor $agentLogPath
    $agentLogCursor.StateWriteTicks=[long]0
    if(Test-Path -LiteralPath $agentStatePath -PathType Leaf){$agentLogCursor.StateWriteTicks=(Get-Item -LiteralPath $agentStatePath).LastWriteTimeUtc.Ticks}
    $agentStartRequestedUtc=[DateTime]::UtcNow
    $agentStartAttempted=$true
    Start-Service WazuhSvc
    $agentService=Get-Service WazuhSvc;$agentService.WaitForStatus('Running',(New-Object TimeSpan(0,0,30)))
    $result.service_status=(Get-Service WazuhSvc).Status.ToString()
    if($result.service_status -ne 'Running'){throw 'WazuhSvc stopped after startup; inspect ossec.log'}
    $serviceStopped=$false
    # Running ещё не означает, что Logcollector открыл JSONL. Ждём свежие подтверждения.
    $readiness=Wait-AgentPasswordReadiness $agentLogPath $agentStatePath $agentLogCursor $agentStartRequestedUtc
    foreach($key in $readiness.Keys){$result[$key]=$readiness[$key]}
    # За время ожидания служба могла остановиться из-за новой конфигурации.
    $result.service_status=(Get-Service WazuhSvc).Status.ToString()
    $serviceDecision=Get-AgentServiceDecision $result.service_status $result.readiness_status
    if($serviceDecision.rollback_required){throw ('WazuhSvc is '+$result.service_status+' after readiness wait; configuration recovery is required')}
    $result.collector_poststart_run_requested=$false
    $postStartRequestedUtc=$agentStartRequestedUtc
    # Контрольный снимок запрашиваем только после открытия файла и подключения к Manager.
    $postStartTask=Get-ExistingTask $taskFolder
    if($readiness.readiness_status -eq 'ready' -and $null -ne $postStartTask) {
        for($taskWait=0;$taskWait -lt 5 -and $postStartTask.State -eq 4;$taskWait++) {
            Start-Sleep -Seconds 2;$postStartTask=Get-ExistingTask $taskFolder
        }
        if($postStartTask.State -eq 4){throw 'Collector task did not finish before the post-start snapshot request'}
        $postStartRequestedUtc=[DateTime]::UtcNow
        [void]$postStartTask.Run($null)
        $result.collector_poststart_run_requested=$true
        $result.collector_poststart_requested_at_utc=$postStartRequestedUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    }
    $result.collector_log_found=$false
    for($attempt=0;$attempt -lt 9;$attempt++) {
        $logs=@(Get-ChildItem -LiteralPath 'C:\SIEM-Audit\Password\logs' -Filter 'password-audit-*.jsonl' -ErrorAction SilentlyContinue|Sort-Object LastWriteTime -Descending)
        if($logs.Count -gt 0) {
            $last=Get-Content -LiteralPath $logs[0].FullName | Select-Object -Last 1
            if($last -and $last -match '"kind"\s*:\s*"summary"' -and
                (!$result.collector_poststart_run_requested -or $logs[0].LastWriteTimeUtc -ge $postStartRequestedUtc)) {
                $result.collector_log_found=$true;$result.collector_summary_json=$last
                $result.collector_log_fresh=$logs[0].LastWriteTimeUtc -ge $postStartRequestedUtc
                if($last -match '"collection_status"\s*:\s*"(ok|partial|error)"'){$result.collector_summary_status=$matches[1]}
                break
            }
        }
        if(!$result.collector_poststart_run_requested){break}
        Start-Sleep -Seconds 5
    }
    $task=Get-ExistingTask $taskFolder
    if($task){$result.task_last_result=[long]$task.LastTaskResult;$result.task_state=[int]$task.State}
    # Финальная проверка после контрольного снимка исключает устаревший Running в отчёте.
    $result.service_status=(Get-Service WazuhSvc).Status.ToString()
    $result.final_service_checked_at_utc=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $serviceDecision=Get-AgentServiceDecision $result.service_status $result.readiness_status
    if($serviceDecision.rollback_required){throw ('WazuhSvc is '+$result.service_status+' after the control snapshot; configuration recovery is required')}
    $result.status='ok'
    if($result.task_status -eq 'existing_preserved' -or !$result.collector_log_found -or $result.collector_summary_status -ne 'ok' -or $result.readiness_status -ne 'ready'){$result.status='partial'}
    Add-Step 'Wazuh service is running; confirm agent status and indexed events on the manager'
} catch {
    $result.status='error';$result.error=$_.Exception.Message
    # Сохраняем диагностический хвост до возможного восстановления конфигурации.
    # В отчёт включаем строки ERROR/WARNING; длинные hex-секреты маскируем.
    try {
        if($agentDirectory) {
            $agentLog=Join-Path $agentDirectory 'ossec.log'
            if(Test-Path -LiteralPath $agentLog -PathType Leaf) {
                $result.agent_error_log_tail=[string[]]@(Get-Content -LiteralPath $agentLog |
                    Select-Object -Last 400 | Where-Object {$_ -match '(?i)\b(ERROR|WARNING)\b'} |
                    Select-Object -Last 20 | ForEach-Object {
                        ([string]$_) -replace '\b[0-9a-fA-F]{64}\b','[REDACTED_HEX64]' -replace '(?i)((?:password|registration_password|auth_key)\s*[:=]\s*)\S+','$1[REDACTED]'
                    })
            }
        }
    } catch {$result.agent_log_read_error=$_.Exception.Message}
    # Восстанавливаем изменённые конфигурацию и ключ при незавершённом развёртывании.
    $rollbackRequested=$serviceStopped -or $configChanged -or $keyChanged -or $agentStartAttempted
    $result.rollback_attempted=[bool]$rollbackRequested
    try {
        if($agentDirectory -and ($configChanged -or $keyChanged)) {
            $rollbackService=Get-Service WazuhSvc
            if($rollbackService.Status -ne 'Stopped') {
                Stop-Service WazuhSvc -Force
                $rollbackService=Get-Service WazuhSvc
                $rollbackService.WaitForStatus('Stopped',(New-Object TimeSpan(0,0,30)))
            }
            if($configChanged -and $configBackup){Copy-Item -LiteralPath $configBackup -Destination (Join-Path $agentDirectory 'ossec.conf') -Force}
            if($keyChanged -and $keyBackup){Copy-Item -LiteralPath $keyBackup -Destination (Join-Path $agentDirectory 'client.keys') -Force;Protect-DeployPath (Join-Path $agentDirectory 'client.keys') $false}
            $result.agent_configuration_rollback='previous_existing_files_restored'
        }
    } catch {$result.rollback_restore_error=$_.Exception.Message}
    # Даже если восстановление файла не удалось, отдельно пробуем поднять службу.
    if($rollbackRequested) {
        try {
            $rollbackService=Get-Service WazuhSvc
            if($rollbackService.Status -ne 'Running'){Start-Service WazuhSvc}
            $rollbackService=Get-Service WazuhSvc
            $rollbackService.WaitForStatus('Running',(New-Object TimeSpan(0,0,30)))
        } catch {$result.rollback_start_error=$_.Exception.Message}
    }
    # Записываем фактически наблюдаемое состояние, включая Stopped/StartPending/отсутствие службы.
    try {$result.service_status=(Get-Service WazuhSvc).Status.ToString()}
    catch {$result.service_status='NotFound';$result.service_status_read_error=$_.Exception.Message}
    $result.service_status_after_rollback=$result.service_status
    $result.service_status_after_rollback_checked_at_utc=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
} finally {
    $result.completed_at_utc=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $report=ConvertTo-DeployJson $result
    # Независимый TEMP-результат сохраняем даже при read-only ISO и ошибке до $staging.
    if($earlyReportPath){
        try{[IO.File]::WriteAllText($earlyReportPath,$report,(New-Object Text.UTF8Encoding($false)))}
        catch{[Console]::Error.WriteLine('Cannot update the independent TEMP deployment report')}
    }
    try{[IO.File]::WriteAllText((Join-Path $sourceDirectory 'deploy-result.json'),$report,(New-Object Text.UTF8Encoding($false)))}
    catch{
        if($staging){[IO.File]::WriteAllText((Join-Path $staging 'deploy-result.json'),$report,(New-Object Text.UTF8Encoding($false)))}
        [Console]::Error.WriteLine('Cannot write the result to the package share; inspect the independent TEMP report shown above or the private staging directory')
    }
    # Не выводим содержимое ключей, пароли и строку ключевого файла в stdout/stderr.
    Write-Output ('Deployment status: '+$result.status+'; run_id='+$runId)
}
if($result.status -eq 'error'){exit 1}
if($result.status -eq 'partial'){exit 3}
exit 0
```
