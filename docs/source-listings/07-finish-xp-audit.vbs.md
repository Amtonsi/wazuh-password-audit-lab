# `finish-xp-audit.vbs`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/finish-xp-audit.vbs). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Завершаем подключение аудита v2 на XP: сохраняем конфиг, подключаем JSONL и создаём отдельную WazuhPasswordAuditV2 от SYSTEM каждый час.

**Применение.** Для первоначального завершения настройки запускаем от администратора: cscript.exe //Nologo C:\Install\windows-password-audit-v2\finish-xp-audit.vbs. Самопроверка: /selftest.

**Особенности.** Старую v1-задачу и её сценарий сохраняем. Имя V2 проверяем до изменений. Совпавшая существующая задача без доказанного расписания даёт needs_review. После создания запускаем через Планировщик и ожидаем новый полный run_id. Отсутствие необязательного executor-окружения не означает неполноту пользовательского снимка.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-16 с BOM. **Объём:** 782 строк.

**SHA256 оригинала:** `09ae6ced4ac61593a31465f3169ad80dd38dbc14b536683d47bb66b62153d7b2`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```vbscript
Option Explicit
' Завершаем аудит XP: отдельная почасовая задача v2, существующую задачу v1 не меняем.
' Ключи агента, пароли и парольную политику не читаем и не изменяем.
If WScript.Arguments.Named.Exists("syntaxcheck") Then
  WScript.Echo "XP finish syntax: PASS"
  WScript.Quit 0
End If
If WScript.Arguments.Named.Exists("selftest") Then
  SelfTest
  WScript.Quit 0
End If
Dim fs, sh, wmi, report, sourceDir, rootDir, logDir, backupDir, agentDir
Dim configPath, configBackup, configChanged
Dim jobPath, collectorPath, runId, code, description, serviceWasStopped, startTimer
Dim taskName, taskExecutable, taskArguments, schedulerPath
Set fs=CreateObject("Scripting.FileSystemObject")
Set sh=CreateObject("WScript.Shell")
Set report=CreateObject("Scripting.Dictionary")
startTimer=Timer
sourceDir=fs.GetParentFolderName(WScript.ScriptFullName)
rootDir="C:\SIEM-Audit\Password"
logDir=rootDir & "\logs"
runId=Replace(Replace(Replace(CStr(Now), ":", ""), "/", ""), " ", "-") & "-" & fs.GetTempName
report("run_id")=runId
report("computer")=sh.ExpandEnvironmentStrings("%COMPUTERNAME%")
report("status")="started"
configChanged=False : serviceWasStopped=False
taskName="WazuhPasswordAuditV2"
report("helper")="finish-xp-audit-v2"
report("legacy_task_status")="untouched"
On Error Resume Next
Main
code=Err.Number : description=Err.Description
Err.Clear
On Error GoTo 0
If code<>0 Then
  report("status")="error"
  report("error")=CStr(code) & ": " & description
  On Error Resume Next
  CaptureAgentErrors
  If configChanged And fs.FileExists(configBackup) Then
    StopAgent
    fs.CopyFile configBackup, configPath, True
    report("configuration_rollback")="restored"
  End If
  If serviceWasStopped Then StartAgent
  If Err.Number<>0 Then report("rollback_error")=CStr(Err.Number) & ": " & Err.Description
  Err.Clear
  On Error GoTo 0
  report("service_status_after_rollback")=CurrentAgentState()
  report("service_status")=report("service_status_after_rollback")
  report("service_state")=report("service_status_after_rollback")
End If
WriteReport
If report("status")="error" Then WScript.Quit 1
If report("status")<>"ok" Then WScript.Quit 3
WScript.Quit 0

Sub Main
  Dim os, version, service, executable, position, parent, item, document, sources, entry
  Dim localfile, node, xmlText, temporary, command, rc, outputPath, placeholder, startCursor, startLocal, ready, sourceCollector
  Dim taskInfo, previousSummary, previousRun, currentSummary, fresh, executorSystem, createdVerified
  Set wmi=GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
  version=""
  For Each os In wmi.ExecQuery("SELECT Version FROM Win32_OperatingSystem")
    version=os.Version
  Next
  If Left(version,3)<>"5.1" Then Err.Raise 513,,"This bootstrap is restricted to Windows XP (5.1)."
  report("os_version")=version
  report("started_at_utc")=UtcStamp()
  Set service=wmi.Get("Win32_Service.Name='WazuhSvc'")
  executable=Trim(service.PathName)
  If Left(executable,1)=Chr(34) Then
    position=InStr(2,executable,Chr(34))
    If position=0 Then Err.Raise 513,,"Cannot parse WazuhSvc executable path."
    executable=Mid(executable,2,position-2)
  Else
    position=InStr(1,executable,".exe",1)
    If position=0 Then Err.Raise 513,,"Cannot parse WazuhSvc executable path."
    executable=Left(executable,position+3)
  End If
  agentDir=fs.GetParentFolderName(executable)
  configPath=fs.BuildPath(agentDir,"ossec.conf")
  If Not fs.FileExists(configPath) Then Err.Raise 513,,"The active ossec.conf was not found."
  report("agent_directory")=agentDir
  collectorPath=fs.BuildPath(rootDir,"collect-password-audit-xp.vbs")
  taskExecutable=sh.ExpandEnvironmentStrings("%SystemRoot%\System32\cscript.exe")
  schedulerPath=sh.ExpandEnvironmentStrings("%SystemRoot%\System32\schtasks.exe")
  taskArguments="//B //Nologo " & collectorPath & " /threshold:60"
  jobPath=sh.ExpandEnvironmentStrings("%SystemRoot%\Tasks\") & taskName & ".job"
  report("task_name")=taskName
  report("task_command")=taskExecutable & " " & taskArguments
  ' При коллизии имени завершаем работу до изменения агента, файлов или задания.
  If fs.FileExists(jobPath) Then
    Set taskInfo=InspectV2Task(jobPath)
    report("task_match")=taskInfo("match")
    If taskInfo("match")<>"exact_enabled" Then
      report("status")="needs_review"
      report("task_status")="existing_v2_name_collision_not_changed"
      report("warning")="Existing V2 task is different, disabled or unreadable; no files or tasks changed."
      Exit Sub
    End If
    report("task_status")="existing_v2_command_verified_preserved"
    report("task_principal_verification")="existing_task_not_read_from_binary_job"
    report("task_schedule_verification")="existing_schedule_preserved_not_reconfigured"
  Else
    report("task_match")="absent"
  End If
  parent=fs.GetParentFolderName(rootDir)
  If fs.FolderExists(parent) Then RejectReparse fs.GetFolder(parent)
  If fs.FolderExists(rootDir) Then RejectReparse fs.GetFolder(rootDir)
  EnsureFolder rootDir
  collectorPath=fs.BuildPath(rootDir,"collect-password-audit-xp.vbs")
  sourceCollector=fs.BuildPath(sourceDir,"collect-password-audit-xp.vbs")
  ' На HGFS прежний файл может оставаться открытым. Версионный payload не затрагивает его.
  If fs.FileExists(fs.BuildPath(sourceDir,"collect-password-audit-xp-v2.vbs")) Then sourceCollector=fs.BuildPath(sourceDir,"collect-password-audit-xp-v2.vbs")
  If Not fs.FileExists(sourceCollector) Then Err.Raise 513,,"Missing XP collector payload."
  If LCase(sourceCollector)<>LCase(collectorPath) Then fs.CopyFile sourceCollector,collectorPath,True
  report("collector_payload")=fs.GetFileName(sourceCollector)

  ' Установочный режим назначает доверенного владельца и проверяет защищённый DACL.
  command=Quote(sh.ExpandEnvironmentStrings("%SystemRoot%\System32\cscript.exe")) & " //B //Nologo " & Quote(collectorPath) & " /secure"
  rc=sh.Run(command,0,True)
  report("secure_exit_code")=rc
  If rc<>0 Then Err.Raise 513,,"Collector ACL setup failed with exit code " & rc
  backupDir=fs.BuildPath(rootDir,"backups\" & fs.GetTempName)
  EnsureFolder backupDir
  configBackup=fs.BuildPath(backupDir,"ossec.conf.before-v2")
  fs.CopyFile configPath,configBackup,False
  report("config_backup")=configBackup

  Set document=CreateObject("Msxml2.DOMDocument.3.0")
  document.async=False
  document.resolveExternals=False
  document.preserveWhiteSpace=True
  If Not document.Load(configPath) Then LoadLegacyXml document,configPath
  If document.documentElement.nodeName<>"ossec_config" Then Err.Raise 513,,"Unexpected ossec.conf root."
  Set sources=document.documentElement.selectNodes("localfile")
  position=0
  For Each entry In sources
    Set node=entry.selectSingleNode("location")
    If Not node Is Nothing Then
      If LCase(node.text)=LCase(logDir & "\password-audit-*.jsonl") Then
        Set node=entry.selectSingleNode("log_format")
        If node Is Nothing Then Err.Raise 513,,"Existing audit source has no log_format."
        If LCase(node.text)<>"json" Then Err.Raise 513,,"Existing audit source is not JSON."
        position=position+1
      End If
    End If
  Next
  If position=0 Then
    Set localfile=document.createElement("localfile")
    Set node=document.createElement("location")
    node.text=logDir & "\password-audit-*.jsonl"
    localfile.appendChild node
    Set node=document.createElement("log_format") : node.text="json"
    localfile.appendChild node
    document.documentElement.appendChild localfile
    report("config_status")="password_v2_source_appended"
  Else
    report("config_status")="existing_password_v2_source_preserved"
  End If
  xmlText=WithoutXmlDeclaration(document.xml)

  ' Старую WazuhPasswordAudit и её скрипт не читаем, не заменяем и не удаляем.
  ' Создаём пустой дневной файл до запуска Logcollector, чтобы последующий снимок не пропускался.
  outputPath=fs.BuildPath(logDir,"password-audit-" & UtcDayKey() & ".jsonl")
  If Not fs.FileExists(outputPath) Then
    Set placeholder=fs.CreateTextFile(outputPath,False,False) : placeholder.Close
  End If
  StopAgent
  temporary=fs.BuildPath(agentDir,"ossec.conf.v2-deploy.tmp")
  WriteUtf8WithoutBom temporary,xmlText
  configChanged=True
  fs.CopyFile temporary,configPath,True
  fs.DeleteFile temporary,False
  Set startCursor=CaptureAgentCursor() : startLocal=Now
  StartAgent
  ready=WaitReady(startCursor,startLocal)
  report("service_status")=CurrentAgentState()
  If report("readiness_status")="error" Then Err.Raise 513,,"WazuhSvc stopped after applying configuration."
  If Not ready Then
    report("status")="partial"
    report("warning")="Service is running, but source/connection readiness was not confirmed within 60 seconds; no control snapshot requested."
    CaptureAgentErrors
    Exit Sub
  End If
  If report("task_match")="absent" Then
    ' /F намеренно не используем: чужую или одновременно созданную задачу не перезаписываем.
    command=Quote(schedulerPath) & " /Create /TN " & Quote(taskName) & " /SC HOURLY /MO 1 /RU SYSTEM /TR " & Quote(fs.GetFile(taskExecutable).ShortPath & " " & taskArguments)
    rc=sh.Run(command,0,True)
    report("task_create_exit_code")=rc
    If rc<>0 Then Err.Raise 513,,"Dedicated V2 task creation failed with exit code " & rc
    If Not fs.FileExists(jobPath) Then Err.Raise 513,,"Task creation returned success but the V2 job was not found."
    Set taskInfo=InspectV2Task(jobPath)
    report("task_match")=taskInfo("match")
    If taskInfo("match")<>"exact_enabled" Then Err.Raise 513,,"Created V2 task command verification failed."
    report("task_status")="created_separate_v2_hourly_system"
    report("task_principal_verification")="created_by_schtasks_ru_system"
    report("task_schedule_verification")="created_by_schtasks_hourly_mo_1"
    report("task_interval_minutes")=60
  End If
  ' Фиксируем предыдущий run_id, чтобы старый JSON не стал доказательством нового запуска.
  previousSummary=LatestSummary()
  previousRun=JsonStringField(previousSummary,"run_id")
  report("previous_collector_run_id")=previousRun
  command=Quote(schedulerPath) & " /Run /TN " & Quote(taskName)
  rc=sh.Run(command,0,True)
  report("task_run_exit_code")=rc
  report("collector_execution")="scheduled_task_after_agent_readiness"
  If rc<>0 Then Err.Raise 513,,"V2 scheduled task launch failed with exit code " & rc
  fresh=WaitFreshSummary(previousRun)
  report("service_status")=CurrentAgentState()
  If report("service_status")<>"Running" Then Err.Raise 513,,"WazuhSvc stopped during the scheduled control snapshot."
  CaptureAgentErrors
  If Not fresh Then
    report("status")="partial"
    report("warning")="Task launch accepted, but a new complete local summary was not confirmed within 60 seconds."
    Exit Sub
  End If
  Set taskInfo=InspectV2Task(jobPath)
  report("task_match_after_run")=taskInfo("match")
  If taskInfo.Exists("status") Then report("task_binary_status_after_run")=taskInfo("status")
  If taskInfo.Exists("exit_code") Then report("task_binary_last_exit_code")=taskInfo("exit_code")
  If taskInfo("match")<>"exact_enabled" Then
    report("status")="needs_review"
    report("warning")="A new complete summary exists, but the V2 task changed during execution."
  Else
    executorSystem=JsonBooleanField(report("collector_summary_json"),"executor_is_system")
    report("collector_executor_account")=JsonStringField(report("collector_summary_json"),"executor_account")
    report("collector_executor_is_system")=executorSystem
    report("collector_executor_identity_source")="process_environment"
    ' Фактическое создание /RU SYSTEM и новый успешный запуск проверяем отдельно от необязательного окружения.
    createdVerified=False
    If report("task_status")="created_separate_v2_hourly_system" Then
      createdVerified=(report("task_create_exit_code")=0 And report("task_run_exit_code")=0 And report("task_principal_verification")="created_by_schtasks_ru_system" And report("task_schedule_verification")="created_by_schtasks_hourly_mo_1")
    End If
    report("task_creation_configuration_verified")=createdVerified
    report("status")=FinalTaskStatus(createdVerified,executorSystem)
    If IsNull(executorSystem) Then report("executor_metadata_status")="unavailable_optional"
    If Not createdVerified Then
      report("warning")="Existing V2 command and new snapshot verified; its pre-existing principal/schedule were preserved and not independently verified."
    ElseIf IsNull(executorSystem) Then
      report("warning")="Task creation under SYSTEM, hourly configuration and new complete run are verified; optional process-environment identity metadata is unavailable. This is not security-token attestation."
    ElseIf Not executorSystem Then
      report("warning")="V2 task produced a snapshot, but process environment does not declare the SYSTEM account; task was not overwritten."
    End If
  End If
End Sub

Sub StopAgent
  Dim service, rc, i
  Set service=wmi.Get("Win32_Service.Name='WazuhSvc'")
  If service.State<>"Stopped" Then
    serviceWasStopped=True
    rc=service.StopService()
    If rc<>0 Then Err.Raise 513,,"StopService returned " & rc
  End If
  For i=1 To 40
    Set service=wmi.Get("Win32_Service.Name='WazuhSvc'")
    If service.State="Stopped" Then serviceWasStopped=True : Exit Sub
    WScript.Sleep 500
  Next
  Err.Raise 513,,"WazuhSvc did not stop."
End Sub
Sub StartAgent
  Dim service, rc, i
  Set service=wmi.Get("Win32_Service.Name='WazuhSvc'")
  If service.State<>"Running" Then
    rc=service.StartService()
    If rc<>0 And rc<>10 Then Err.Raise 513,,"StartService returned " & rc
  End If
  For i=1 To 40
    Set service=wmi.Get("Win32_Service.Name='WazuhSvc'")
    If service.State="Running" Then serviceWasStopped=False : Exit Sub
    WScript.Sleep 500
  Next
  Err.Raise 513,,"WazuhSvc did not start."
End Sub
Function FinalTaskStatus(createdConfigurationVerified,executorSystem)
  FinalTaskStatus="needs_review"
  If Not createdConfigurationVerified Then Exit Function
  ' Отсутствие необязательной метаинформации не отменяет проверенный /RU SYSTEM и новый полный запуск.
  If IsNull(executorSystem) Then
    FinalTaskStatus="ok"
  ElseIf executorSystem Then
    FinalTaskStatus="ok"
  End If
End Function
Function InspectV2Task(path)
  Dim result, binary, document, node, hexText, metadata, match, code
  Set result=CreateObject("Scripting.Dictionary")
  result("match")="unreadable"
  On Error Resume Next
  Set binary=CreateObject("ADODB.Stream")
  binary.Type=1 : binary.Open : binary.LoadFromFile path
  If Err.Number=0 Then
    If binary.Size>=68 And binary.Size<=1048576 Then
      Set document=CreateObject("Msxml2.DOMDocument.3.0")
      Set node=document.createElement("job") : node.dataType="bin.hex"
      node.nodeTypedValue=binary.Read
      hexText=Replace(Replace(Replace(Replace(node.text," ",""),vbCr,""),vbLf,""),vbTab,"")
      Set metadata=ParseJobHex(hexText)
      If Err.Number=0 Then
        result("status")=metadata("status")
        result("exit_code")=metadata("exit_code")
        match=TaskCommandMatch(metadata("application"),metadata("arguments"),metadata("flags"),metadata("status"),taskExecutable,taskArguments)
        result("match")=match
      End If
    End If
  End If
  code=Err.Number : Err.Clear
  If Not binary Is Nothing Then binary.Close
  Err.Clear : On Error GoTo 0
  Set InspectV2Task=result
End Function
Function ParseJobHex(text)
  Dim result, position
  If Len(text)<136 Or (Len(text) Mod 2)<>0 Then Err.Raise 513,,"Invalid job length."
  If JobWord(text,2)<>1 Then Err.Raise 513,,"Unsupported job format version."
  position=JobWord(text,20)
  If position<68 Or position>=Len(text)\2 Then Err.Raise 513,,"Invalid job application offset."
  Set result=CreateObject("Scripting.Dictionary")
  result("application")=JobString(text,position)
  result("arguments")=JobString(text,position)
  result("exit_code")=JobDword(text,40)
  result("status")=JobDword(text,44)
  result("flags")=JobDword(text,48)
  Set ParseJobHex=result
End Function
Function JobByte(text,position)
  If position<0 Or position*2+2>Len(text) Then Err.Raise 513,,"Job field outside file."
  JobByte=CLng("&H" & Mid(text,position*2+1,2))
End Function
Function JobWord(text,position)
  JobWord=JobByte(text,position)+256*JobByte(text,position+1)
End Function
Function JobDword(text,position)
  JobDword=CDbl(JobByte(text,position))+256.0*JobByte(text,position+1)+65536.0*JobByte(text,position+2)+16777216.0*JobByte(text,position+3)
End Function
Function JobString(text,ByRef position)
  Dim count, i, n, result
  count=JobWord(text,position) : position=position+2 : result=""
  If count=0 Then JobString="" : Exit Function
  If count>32768 Or (position+count*2)*2>Len(text) Then Err.Raise 513,,"Invalid job Unicode string length."
  For i=0 To count-1
    n=JobWord(text,position+i*2)
    If i=count-1 Then
      If n<>0 Then Err.Raise 513,,"Job Unicode string has no null terminator."
    Else
      If n=0 Then Err.Raise 513,,"Unexpected null in job string."
      If n>32767 Then n=n-65536
      result=result & ChrW(n)
    End If
  Next
  position=position+count*2 : JobString=result
End Function
Function TaskCommandMatch(application,arguments,flags,status,expectedExecutable,expectedArguments)
  TaskCommandMatch="different_command"
  If NormalizedArguments(arguments)<>NormalizedArguments(expectedArguments) Then Exit Function
  If Not SameExecutable(application,expectedExecutable) Then Exit Function
  If (CLng(flags) And 4)<>0 Or CDbl(status)=267010 Then
    TaskCommandMatch="disabled"
  Else
    TaskCommandMatch="exact_enabled"
  End If
End Function
Function SameExecutable(actual,expected)
  Dim a,b,shortA,shortB
  a=LCase(Trim(Replace(sh.ExpandEnvironmentStrings(actual),Chr(34),"")))
  b=LCase(Trim(Replace(sh.ExpandEnvironmentStrings(expected),Chr(34),"")))
  SameExecutable=(a=b)
  If SameExecutable Then Exit Function
  On Error Resume Next
  shortA="" : shortB=""
  If fs.FileExists(a) Then shortA=LCase(fs.GetFile(a).ShortPath)
  If fs.FileExists(b) Then shortB=LCase(fs.GetFile(b).ShortPath)
  If Err.Number=0 And Len(shortA)>0 And Len(shortB)>0 Then SameExecutable=(shortA=shortB)
  Err.Clear : On Error GoTo 0
End Function
Function NormalizedArguments(text)
  Dim expression
  Set expression=New RegExp : expression.Pattern="\s+" : expression.Global=True
  NormalizedArguments=LCase(Trim(expression.Replace(Replace(text,Chr(34),"")," ")))
End Function
Function JsonStringField(text,name)
  Dim expression,matches
  Set expression=New RegExp
  expression.Pattern=Chr(34) & name & Chr(34) & "\s*:\s*" & Chr(34) & "([^" & Chr(34) & "]*)" & Chr(34)
  expression.Global=False
  Set matches=expression.Execute(text)
  JsonStringField=""
  If matches.Count>0 Then JsonStringField=matches(0).SubMatches(0)
End Function
Function JsonBooleanField(text,name)
  Dim expression,matches
  Set expression=New RegExp
  expression.Pattern=Chr(34) & name & Chr(34) & "\s*:\s*(true|false|null)"
  expression.Global=False
  Set matches=expression.Execute(text)
  JsonBooleanField=Null
  If matches.Count=0 Then Exit Function
  If matches(0).SubMatches(0)="true" Then JsonBooleanField=True
  If matches(0).SubMatches(0)="false" Then JsonBooleanField=False
End Function
Function CompleteSummary(text)
  Dim expression
  Set expression=New RegExp
  expression.Pattern=Chr(34) & "enumeration_complete" & Chr(34) & "\s*:\s*true"
  CompleteSummary=False
  If Not expression.Test(text) Then Exit Function
  expression.Pattern=Chr(34) & "identity_complete" & Chr(34) & "\s*:\s*true"
  If Not expression.Test(text) Then Exit Function
  If JsonStringField(text,"collection_status")<>"ok" Then Exit Function
  If JsonStringField(text,"scope")<>"local_sam_metadata" Then Exit Function
  CompleteSummary=True
End Function
Function LatestSummary()
  Dim path,stream,lines,i
  LatestSummary=""
  path=fs.BuildPath(logDir,"password-audit-" & UtcDayKey() & ".jsonl")
  If Not fs.FileExists(path) Then Exit Function
  Set stream=fs.OpenTextFile(path,1,False,0) : lines=Split(stream.ReadAll,vbLf) : stream.Close
  For i=UBound(lines) To 0 Step -1
    If JsonStringField(lines(i),"kind")="summary" Then LatestSummary=Trim(lines(i)) : Exit Function
  Next
End Function
Function IsNewRun(previousRun,text)
  Dim current
  current=JsonStringField(text,"run_id")
  IsNewRun=(Len(current)>0 And current<>previousRun)
End Function
Function WaitFreshSummary(previousRun)
  Dim started,text
  started=Timer : WaitFreshSummary=False
  Do While SessionElapsed(started)<60
    If CurrentAgentState()<>"Running" Then Err.Raise 513,,"WazuhSvc stopped while waiting for the scheduled snapshot."
    text=LatestSummary()
    If IsNewRun(previousRun,text) Then
      report("collector_run_id")=JsonStringField(text,"run_id")
      report("collector_summary_json")=text
      report("collector_new_run_confirmed")=True
      report("collector_complete")=CompleteSummary(text)
      WaitFreshSummary=CompleteSummary(text)
      Exit Function
    End If
    WScript.Sleep 1000
  Loop
  report("collector_new_run_confirmed")=False
End Function
Function WithoutXmlDeclaration(text)
  Dim position
  text=Trim(text)
  If Left(text,1)=ChrW(-257) Then text=Mid(text,2)
  If LCase(Left(text,5))="<?xml" Then
    position=InStr(text,"?>")
    If position=0 Then Err.Raise 513,,"Invalid XML declaration."
    text=Mid(text,position+2)
  End If
  WithoutXmlDeclaration=Trim(text) & vbCrLf
End Function
Sub LoadLegacyXml(document,path)
  Dim originalReason, originalLine, originalPosition, binary, bytes, valid, text
  originalReason=document.parseError.reason
  originalLine=document.parseError.line
  originalPosition=document.parseError.linepos
  report("original_xml_error")=originalReason
  report("original_xml_error_line")=originalLine
  report("original_xml_error_position")=originalPosition
  Set binary=CreateObject("ADODB.Stream")
  binary.Type=1 : binary.Open : binary.LoadFromFile path
  valid=True
  If binary.Size>0 Then bytes=binary.Read : valid=ValidUtf8Bytes(bytes)
  binary.Close
  ' Корректный UTF-8 с ошибкой синтаксиса не перекодируем.
  If valid Then Err.Raise 513,,"XML syntax failed in valid UTF-8; encoding unchanged: " & originalReason
  Set binary=CreateObject("ADODB.Stream")
  binary.Type=2 : binary.Charset="windows-1251" : binary.Open : binary.LoadFromFile path
  text=binary.ReadText : binary.Close
  ' Исправление ограничиваем CP1251-комментариями; кодировку рабочих значений не угадываем.
  If Not AsciiOutsideComments(text) Then Err.Raise 513,,"Legacy encoding affects XML values; manual review is required."
  If Not document.LoadXML(text) Then Err.Raise 513,,"CP1251 fallback XML load failed: " & document.parseError.reason
  report("config_encoding_handling")="windows-1251_comments_to_utf8_without_bom"
End Sub
Function AsciiOutsideComments(text)
  Dim expression, outside, i, n
  Set expression=New RegExp
  expression.Pattern="<!--[\s\S]*?-->" : expression.Global=True
  outside=expression.Replace(text,"")
  AsciiOutsideComments=False
  For i=1 To Len(outside)
    n=AscW(Mid(outside,i,1)) : If n<0 Then n=n+65536
    If n>127 Then Exit Function
  Next
  AsciiOutsideComments=True
End Function
Function ValidUtf8Bytes(bytes)
  Dim i, last, a, b, needed, j, values, document, node, hexText
  ' ADODB возвращает SAFEARRAY(Byte), элементы которого WSH нельзя читать как bytes(i).
  ' Преобразуем его через документированный MSXML bin.hex в обычный массив Variant.
  If VarType(bytes)=8209 Then
    Set document=CreateObject("Msxml2.DOMDocument.3.0")
    Set node=document.createElement("bytes")
    node.dataType="bin.hex" : node.nodeTypedValue=bytes
    hexText=Replace(Replace(Replace(Replace(node.text," ",""),vbCr,""),vbLf,""),vbTab,"")
    If Len(hexText)=0 Then ValidUtf8Bytes=True : Exit Function
    ReDim values((Len(hexText)\2)-1)
    For i=0 To UBound(values)
      values(i)=CLng("&H" & Mid(hexText,i*2+1,2))
    Next
  Else
    values=bytes
  End If
  ValidUtf8Bytes=False : i=LBound(values) : last=UBound(values)
  Do While i<=last
    a=CLng(values(i)) : needed=0
    If a<128 Then
      i=i+1
    Else
      If a>=194 And a<=223 Then needed=1
      If a>=224 And a<=239 Then needed=2
      If a>=240 And a<=244 Then needed=3
      If needed=0 Or i+needed>last Then Exit Function
      For j=1 To needed
        b=CLng(values(i+j))
        If b<128 Or b>191 Then Exit Function
      Next
      b=CLng(values(i+1))
      If a=224 And b<160 Then Exit Function
      If a=237 And b>=160 Then Exit Function
      If a=240 And b<144 Then Exit Function
      If a=244 And b>143 Then Exit Function
      i=i+needed+1
    End If
  Loop
  ValidUtf8Bytes=True
End Function
Sub WriteUtf8WithoutBom(path,text)
  Dim encoded, output, bytes
  Set encoded=CreateObject("ADODB.Stream")
  encoded.Type=2 : encoded.Charset="utf-8" : encoded.Open : encoded.WriteText text
  encoded.Position=0 : encoded.Type=1 : encoded.Position=3 : bytes=encoded.Read : encoded.Close
  Set output=CreateObject("ADODB.Stream")
  output.Type=1 : output.Open : output.Write bytes : output.SaveToFile path,2 : output.Close
End Sub
Sub CaptureAgentErrors
  Dim path, stream, lines, i, first, text, expression
  If Len(agentDir)=0 Then Exit Sub
  path=fs.BuildPath(agentDir,"ossec.log")
  If Not fs.FileExists(path) Then Exit Sub
  Set stream=fs.OpenTextFile(path,1,False,0) : lines=Split(stream.ReadAll,vbLf) : stream.Close
  first=UBound(lines)-200 : If first<0 Then first=0
  text=""
  Set expression=New RegExp : expression.Pattern="[0-9A-Fa-f]{64}" : expression.Global=True
  For i=first To UBound(lines)
    If InStr(1,lines(i),"ERROR",1)>0 Or InStr(1,lines(i),"WARNING",1)>0 Then
      text=text & expression.Replace(lines(i),"[REDACTED_HEX64]") & vbLf
    End If
  Next
  report("agent_error_log_tail")=text
End Sub
Sub WriteReport
  Dim path, output, text
  On Error Resume Next
  report("completed_at_utc")=UtcStamp()
  Err.Clear
  text=JsonValue(report)
  path=fs.BuildPath(sourceDir,"finish-xp-result.json")
  Set output=fs.CreateTextFile(path,True,False)
  If Err.Number<>0 Then
    Err.Clear : path=fs.BuildPath(rootDir,"finish-xp-result.json")
    Set output=fs.CreateTextFile(path,True,False)
  End If
  If Err.Number=0 Then output.WriteLine text : output.Close
  Err.Clear
  On Error GoTo 0
End Sub
Function JsonValue(value)
  Dim text, key, first
  If IsObject(value) Then
    text="{" : first=True
    For Each key In value.Keys
      If Not first Then text=text & ","
      text=text & J(key) & ":" & JsonValue(value(key)) : first=False
    Next
    JsonValue=text & "}"
  ElseIf IsNull(value) Or IsEmpty(value) Then
    JsonValue="null"
  ElseIf VarType(value)=11 Then
    If value Then JsonValue="true" Else JsonValue="false"
  ElseIf IsNumeric(value) And VarType(value)<>8 Then
    JsonValue=CStr(value)
  Else
    JsonValue=J(CStr(value))
  End If
End Function
Function J(text)
  Dim result, i, n, ch
  result=Chr(34)
  For i=1 To Len(CStr(text))
    ch=Mid(CStr(text),i,1) : n=AscW(ch) : If n<0 Then n=n+65536
    If n=34 Or n=92 Then
      result=result & Chr(92) & ch
    ElseIf n<32 Or n>126 Then
      result=result & Chr(92) & "u" & Right("0000" & Hex(n),4)
    Else
      result=result & ch
    End If
  Next
  J=result & Chr(34)
End Function
Function UtcValue()
  Dim dateTime
  Set dateTime=CreateObject("WbemScripting.SWbemDateTime")
  dateTime.SetVarDate Now,True : UtcValue=dateTime.GetVarDate(False)
End Function
Function UtcStamp()
  Dim value
  value=UtcValue()
  UtcStamp=Year(value)&"-"&Right("0"&Month(value),2)&"-"&Right("0"&Day(value),2)&"T"&Right("0"&Hour(value),2)&":"&Right("0"&Minute(value),2)&":"&Right("0"&Second(value),2)&"Z"
End Function
Function UtcDayKey()
  Dim value
  value=UtcValue() : UtcDayKey=Year(value)&Right("0"&Month(value),2)&Right("0"&Day(value),2)
End Function
Function Quote(value)
  Quote=Chr(34)&value&Chr(34)
End Function
Sub EnsureFolder(path)
  Dim parent
  If fs.FolderExists(path) Then Exit Sub
  parent=fs.GetParentFolderName(path)
  If Len(parent)>0 And Not fs.FolderExists(parent) Then EnsureFolder parent
  fs.CreateFolder path
End Sub
Sub RejectReparse(obj)
  If (obj.Attributes And 1024)<>0 Then Err.Raise 513,,"Reparse point rejected: " & obj.Path
End Sub
Sub SelfTest
  Dim text, value, dictionary, document, ado, bytes, metadata, hexText, jobError
  text=WithoutXmlDeclaration("<?xml version=""1.0"" encoding=""UTF-8""?>" & vbCrLf & "<ossec_config/>")
  If InStr(text,"<?xml")>0 Or Left(text,1)=ChrW(-257) Then Err.Raise 513,,"XML declaration removal failed"
  Set document=CreateObject("Msxml2.DOMDocument.3.0")
  document.async=False : document.resolveExternals=False
  If Not document.LoadXML(text) Then Err.Raise 513,,"Declaration-free XML failed to parse"
  Set fs=CreateObject("Scripting.FileSystemObject")
  Set sh=CreateObject("WScript.Shell")
  hexText=String(136,"0")
  hexText=Left(hexText,4) & "0100" & Mid(hexText,9)
  hexText=Left(hexText,40) & "4400" & Mid(hexText,45)
  hexText=hexText & JobTestString("C:\Windows\System32\cscript.exe") & JobTestString("//B //Nologo C:\SIEM-Audit\Password\collect-password-audit-xp.vbs /threshold:60")
  Set metadata=ParseJobHex(hexText)
  If metadata("application")<>"C:\Windows\System32\cscript.exe" Then Err.Raise 513,,"Binary job application parsing failed."
  If TaskCommandMatch(metadata("application"),metadata("arguments"),0,267011,"C:\Windows\System32\cscript.exe",metadata("arguments"))<>"exact_enabled" Then Err.Raise 513,,"Matching job rejected."
  If TaskCommandMatch(metadata("application"),metadata("arguments") & " /evil",0,267008,"C:\Windows\System32\cscript.exe",metadata("arguments"))<>"different_command" Then Err.Raise 513,,"Colliding task command accepted."
  If TaskCommandMatch(metadata("application"),metadata("arguments"),4,267008,"C:\Windows\System32\cscript.exe",metadata("arguments"))<>"disabled" Then Err.Raise 513,,"Disabled job accepted."
  On Error Resume Next
  Set metadata=ParseJobHex(Left(hexText,Len(hexText)-4))
  jobError=Err.Number : Err.Clear : On Error GoTo 0
  If jobError=0 Then Err.Raise 513,,"Truncated job accepted."
  If FinalTaskStatus(True,Null)<>"ok" Then Err.Raise 513,,"Optional missing executor metadata must not fail a verified new task."
  If FinalTaskStatus(False,Null)<>"needs_review" Then Err.Raise 513,,"Existing unverified task must stay needs_review."
  If FinalTaskStatus(False,True)<>"needs_review" Then Err.Raise 513,,"Executor metadata cannot prove an existing schedule."
  If FinalTaskStatus(True,False)<>"needs_review" Then Err.Raise 513,,"Conflicting executor metadata must remain visible."
  If Not IsNull(JsonBooleanField("{}","executor_is_system")) Then Err.Raise 513,,"Unknown executor metadata must stay null."
  If IsNewRun("old","{""run_id"":""old""}") Then Err.Raise 513,,"Old summary accepted as fresh."
  If Not IsNewRun("old","{""run_id"":""new""}") Then Err.Raise 513,,"Fresh summary rejected."
  text="{""kind"":""summary"",""run_id"":""new"",""collection_status"":""ok"",""enumeration_complete"":true,""identity_complete"":true,""scope"":""local_sam_metadata""}"
  If Not CompleteSummary(text) Then Err.Raise 513,,"Complete summary rejected."
  If CompleteSummary(Replace(text,"""identity_complete"":true","""identity_complete"":false")) Then Err.Raise 513,,"Incomplete summary accepted."
  Set dictionary=CreateObject("Scripting.Dictionary")
  dictionary("ok")=True : dictionary("name")=ChrW(1040)
  value=JsonValue(dictionary)
  If InStr(value,"""ok"":true")=0 Or InStr(value,"\u0410")=0 Then Err.Raise 513,,"JSON serialization failed"
  If Not ValidUtf8Bytes(Array(65,208,144)) Then Err.Raise 513,,"Valid UTF-8 failed"
  If ValidUtf8Bytes(Array(228,229)) Then Err.Raise 513,,"CP1251 mistaken for UTF-8"
  If ValidUtf8Bytes(Array(224,128,128)) Then Err.Raise 513,,"Overlong UTF-8 accepted"
  If Not AsciiOutsideComments("<!--" & ChrW(1040) & "--><ossec_config/>") Then Err.Raise 513,,"Comment-only fallback failed"
  If AsciiOutsideComments("<location>" & ChrW(1040) & "</location>") Then Err.Raise 513,,"Non-ASCII configuration value was not rejected"
  Set ado=CreateObject("ADODB.Stream")
  ado.Type=2 : ado.Charset="windows-1251" : ado.Open
  ado.WriteText "<!--" & ChrW(1040) & ChrW(1041) & "--><ossec_config/>"
  ado.Position=0 : ado.Type=1 : bytes=ado.Read : ado.Close
  If ValidUtf8Bytes(bytes) Then Err.Raise 513,,"Real ADODB CP1251 bytes mistaken for UTF-8"
  If ReadinessOutcome("Stopped",True,True)<>"error" Then Err.Raise 513,,"Stopped-after-start must be an error."
  If ReadinessOutcome("Running",True,False)<>"partial" Then Err.Raise 513,,"Running without connection must remain partial."
  If ReadinessOutcome("Running",True,True)<>"ready" Then Err.Raise 513,,"Ready service/source/connection failed."
  WScript.Echo "XP finish pure self-tests: PASS"
End Sub

Function CurrentAgentState()
  Dim service, code, message
  On Error Resume Next
  Set service=wmi.Get("Win32_Service.Name='WazuhSvc'")
  code=Err.Number : message=Err.Description : Err.Clear
  If code=0 Then
    CurrentAgentState=service.State
  Else
    CurrentAgentState="Unknown"
    report("service_state_read_error")=CStr(code) & ": " & message
  End If
  On Error GoTo 0
End Function
Function ReadinessOutcome(state,analyzed,connected)
  If LCase(state)<>"running" Then
    ReadinessOutcome="error"
  ElseIf analyzed And connected Then
    ReadinessOutcome="ready"
  Else
    ReadinessOutcome="partial"
  End If
End Function
Function ReadAgentText(path)
  Dim stream
  Set stream=fs.OpenTextFile(path,1,False,0)
  ReadAgentText=stream.ReadAll : stream.Close
End Function
Function CaptureAgentCursor()
  Dim result,path
  Set result=CreateObject("Scripting.Dictionary")
  result("offset")=0 : result("created")=""
  path=fs.BuildPath(agentDir,"ossec.log")
  If fs.FileExists(path) Then
    result("offset")=Len(ReadAgentText(path))
    result("created")=CStr(fs.GetFile(path).DateCreated)
  End If
  Set CaptureAgentCursor=result
End Function
Function WaitReady(cursor,startLocal)
  Dim started,lines,line,path,text,offset,analyzed,connected,current,expression,matches
  started=Timer : analyzed=False : connected=False
  Set expression=New RegExp
  expression.Pattern="^\s*status\s*=\s*['" & Chr(34) & "]?([A-Za-z_]+)['" & Chr(34) & "]?\s*$"
  expression.Global=False : expression.IgnoreCase=True : expression.MultiLine=True
  Do While SessionElapsed(started)<60 And SessionElapsed(startTimer)<1200
    path=fs.BuildPath(agentDir,"ossec.log")
    If fs.FileExists(path) Then
      text=ReadAgentText(path) : offset=cursor("offset")
      If Len(text)<offset Or CStr(fs.GetFile(path).DateCreated)<>cursor("created") Then offset=0
      lines=Split(Mid(text,offset+1),vbLf)
      For Each line In lines
        line=Replace(line,"/","\")
        If InStr(1,line,"Analyzing file",1)>0 And InStr(1,line,"\siem-audit\password\logs\password-audit-",1)>0 Then analyzed=True
        If InStr(1,line,"Connected to",1)>0 And InStr(1,line,"not connected",1)=0 Then connected=True
        If InStr(1,line,"Lost connection",1)>0 Or InStr(1,line,"Disconnected",1)>0 Then connected=False
      Next
    End If
    path=fs.BuildPath(agentDir,"wazuh-agent.state")
    If fs.FileExists(path) Then
      If fs.GetFile(path).DateLastModified>=startLocal Then
        Set matches=expression.Execute(ReadAgentText(path))
        If matches.Count>0 Then connected=(LCase(matches(0).SubMatches(0))="connected")
      End If
    End If
    current=CurrentAgentState()
    If current<>"Running" Or (analyzed And connected) Then Exit Do
    WScript.Sleep 1000
  Loop
  current=CurrentAgentState()
  report("readiness_file_analyzing")=analyzed
  report("readiness_connected")=connected
  report("service_state_at_readiness_end")=current
  report("service_state")=current
  report("readiness_status")=ReadinessOutcome(current,analyzed,connected)
  WaitReady=(report("readiness_status")="ready")
End Function
Function SessionElapsed(started)
  Dim value
  value=Timer-started : If value<0 Then value=value+86400
  SessionElapsed=value
End Function

Function JobTestString(text)
  Dim length,i,n,result
  length=Len(text)+1
  result=Right("0" & Hex(length Mod 256),2) & Right("0" & Hex(length\256),2)
  For i=1 To Len(text)
    n=AscW(Mid(text,i,1)) : If n<0 Then n=n+65536
    result=result & Right("0" & Hex(n Mod 256),2) & Right("0" & Hex(n\256),2)
  Next
  JobTestString=result & "0000"
End Function
```
