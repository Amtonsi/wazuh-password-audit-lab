# `deploy-xp.vbs`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/deploy-xp.vbs). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Вспомогательный сценарий первоначальной миграции XP: подготавливаем каталог и конфиг v2, анализируем прежнюю задачу, сохраняем резервные материалы.

**Применение.** Изучаем и применяем только при соответствующем сценарии первоначальной миграции. В выполненном итоговом порядке XP используем finish-xp-audit.vbs.

**Особенности.** Может работать с подтверждённой legacy-задачей и wrapper прежнего сборщика; неизвестную задачу оставляет для проверки. Поэтому этот файл не считаем взаимозаменяемым с финальным finish-сценарием. Исходник сохранён полностью.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-16 с BOM. **Объём:** 598 строк.

**SHA256 оригинала:** `7e773fa80e14106ec73fbff6cb1b4c510d1666fc4239f91966525b42bce03a1c`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```vbscript
Option Explicit
' Однократное развёртывание v2 на существующей Windows XP из локальной/HGFS-папки.
' Ключи агента, пароли и парольную политику не читаем и не изменяем.
If WScript.Arguments.Named.Exists("syntaxcheck") Then
  WScript.Echo "XP bootstrap syntax: PASS"
  WScript.Quit 0
End If
If WScript.Arguments.Named.Exists("selftest") Then
  SelfTest
  WScript.Quit 0
End If
Dim fs, sh, wmi, report, sourceDir, rootDir, logDir, backupDir, agentDir
Dim configPath, configBackup, oldCollector, oldBackup, wrapperChanged, configChanged
Dim jobPath, collectorPath, runId, code, description, serviceWasStopped, startTimer
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
configChanged=False : wrapperChanged=False : serviceWasStopped=False
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
  If wrapperChanged And fs.FileExists(oldBackup) Then
    fs.CopyFile oldBackup, oldCollector, True
    report("wrapper_rollback")="restored"
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
  Dim localfile, node, xmlText, temporary, command, rc, taskKind, outputPath, placeholder, startCursor, startLocal, ready
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
  parent=fs.GetParentFolderName(rootDir)
  If fs.FolderExists(parent) Then RejectReparse fs.GetFolder(parent)
  If fs.FolderExists(rootDir) Then RejectReparse fs.GetFolder(rootDir)
  EnsureFolder rootDir
  collectorPath=fs.BuildPath(rootDir,"collect-password-audit-xp.vbs")
  For Each item In Array("collect-password-audit-xp.vbs","install-task-xp.cmd")
    If Not fs.FileExists(fs.BuildPath(sourceDir,item)) Then Err.Raise 513,,"Missing package file: " & item
    If LCase(sourceDir)<>LCase(rootDir) Then fs.CopyFile fs.BuildPath(sourceDir,item),fs.BuildPath(rootDir,item),True
  Next

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

  oldCollector=fs.BuildPath(agentDir,"custom\password-audit\collect-password-audit.vbs")
  jobPath=sh.ExpandEnvironmentStrings("%SystemRoot%\Tasks\WazuhPasswordAudit.job")
  taskKind="absent"
  If fs.FileExists(jobPath) Then taskKind=InspectTask(oldCollector,collectorPath)
  report("task_kind")=taskKind
  If taskKind="legacy" Then
    oldBackup=fs.BuildPath(backupDir,"collect-password-audit.v1.vbs")
    fs.CopyFile oldCollector,oldBackup,False
    report("legacy_collector_backup")=oldBackup
    WriteWrapper oldCollector,collectorPath
    wrapperChanged=True
    report("task_status")="existing_job_preserved_legacy_script_wrapped"
  ElseIf taskKind="v2" Then
    report("task_status")="existing_v2_job_preserved"
  ElseIf taskKind="absent" Then
    command=Quote(sh.ExpandEnvironmentStrings("%SystemRoot%\System32\cmd.exe")) & " /d /s /c " & Quote(Quote(fs.BuildPath(rootDir,"install-task-xp.cmd")))
    rc=sh.Run(command,0,True)
    report("task_setup_exit_code")=rc
    If rc<>0 Then Err.Raise 513,,"XP task installation failed with exit code " & rc
    report("task_status")="created"
  Else
    report("task_status")="needs_review_existing_job_not_changed"
  End If

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
  ' После запуска агента выполняем новый синхронный снимок; существующее расписание сохраняем.
  command=Quote(sh.ExpandEnvironmentStrings("%SystemRoot%\System32\cscript.exe")) & " //B //Nologo " & Quote(collectorPath) & " /threshold:60"
  rc=sh.Run(command,0,True)
  report("collector_execution")="direct_after_agent_start"
  report("collector_exit_code")=rc
  report("service_status")=CurrentAgentState()
  If report("service_status")<>"Running" Then Err.Raise 513,,"WazuhSvc stopped during the control snapshot."
  CaptureSummary
  CaptureAgentErrors
  report("status")="ok"
  If rc<>0 Then report("status")="partial"
  If taskKind="unknown" Then report("status")="needs_review"
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
Function InspectTask(legacyPath,v2Path)
  Dim queryFile, command, rc, stream, text, line, fields, value, taskRow, normalized, shortLegacy, shortV2
  InspectTask="unknown"
  queryFile=fs.BuildPath(backupDir,"tasks-query.csv")
  command=Quote(sh.ExpandEnvironmentStrings("%SystemRoot%\System32\cmd.exe")) & " /d /s /c " & Quote(Quote(sh.ExpandEnvironmentStrings("%SystemRoot%\System32\schtasks.exe")) & " /Query /FO CSV /V > " & Quote(queryFile) & " 2>&1")
  rc=sh.Run(command,0,True)
  If rc<>0 Or Not fs.FileExists(queryFile) Then Exit Function
  Set stream=fs.OpenTextFile(queryFile,1,False,0) : text=stream.ReadAll : stream.Close
  shortLegacy="" : shortV2=""
  If fs.FileExists(legacyPath) Then shortLegacy=LCase(fs.GetFile(legacyPath).ShortPath)
  If fs.FileExists(v2Path) Then shortV2=LCase(fs.GetFile(v2Path).ShortPath)
  For Each line In Split(Replace(text,vbCr,""),vbLf)
    fields=ParseCsv(line) : taskRow=False
    For Each value In fields
      normalized=LCase(Trim(value))
      If normalized="wazuhpasswordaudit" Or normalized="\wazuhpasswordaudit" Then taskRow=True
    Next
    If taskRow Then
      For Each value In fields
        normalized=LCase(Replace(sh.ExpandEnvironmentStrings(value),Chr(34),""))
        If InStr(normalized,"cscript")>0 Then
          If InStr(normalized,LCase(v2Path))>0 Or (Len(shortV2)>0 And InStr(normalized,shortV2)>0) Then InspectTask="v2" : Exit Function
          If fs.FileExists(legacyPath) Then
            If InStr(normalized,LCase(legacyPath))>0 Or (Len(shortLegacy)>0 And InStr(normalized,shortLegacy)>0) Then InspectTask="legacy" : Exit Function
          End If
        End If
      Next
    End If
  Next
End Function
Function ParseCsv(text)
  Dim fields(), index, i, ch, quoted, current
  ReDim fields(0) : index=0 : current="" : quoted=False : i=1
  Do While i<=Len(text)
    ch=Mid(text,i,1)
    If ch=Chr(34) Then
      If quoted And i<Len(text) And Mid(text,i+1,1)=Chr(34) Then
        current=current & Chr(34) : i=i+1
      Else
        quoted=Not quoted
      End If
    ElseIf ch="," And Not quoted Then
      fields(index)=current : index=index+1 : ReDim Preserve fields(index) : current=""
    Else
      current=current & ch
    End If
    i=i+1
  Loop
  fields(index)=current : ParseCsv=fields
End Function
Sub WriteWrapper(path,target)
  Dim text, output, command
  command=Quote(sh.ExpandEnvironmentStrings("%SystemRoot%\System32\cscript.exe")) & " //B //Nologo " & Quote(target) & " /threshold:60"
  text="Option Explicit" & vbCrLf & "Dim sh, rc" & vbCrLf & "Set sh=CreateObject(""WScript.Shell"")" & vbCrLf
  text=text & "rc=sh.Run(" & VbsLiteral(command) & ",0,True)" & vbCrLf & "WScript.Quit rc" & vbCrLf
  Set output=fs.CreateTextFile(path,True,True) : output.Write text : output.Close
End Sub
Function VbsLiteral(text)
  VbsLiteral=Chr(34) & Replace(text,Chr(34),Chr(34)&Chr(34)) & Chr(34)
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
Sub CaptureSummary
  Dim path, stream, lines, i
  path=fs.BuildPath(logDir,"password-audit-" & UtcDayKey() & ".jsonl")
  If Not fs.FileExists(path) Then Exit Sub
  Set stream=fs.OpenTextFile(path,1,False,0) : lines=Split(stream.ReadAll,vbLf) : stream.Close
  For i=UBound(lines) To 0 Step -1
    If InStr(lines(i),"""kind"":""summary""")>0 Then
      report("collector_summary_json")=Trim(lines(i)) : Exit Sub
    End If
  Next
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
  path=fs.BuildPath(sourceDir,"deploy-result.json")
  Set output=fs.CreateTextFile(path,True,False)
  If Err.Number<>0 Then
    Err.Clear : path=fs.BuildPath(rootDir,"deploy-result.json")
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
  Dim text, fields, value, dictionary, document, ado, bytes
  text=WithoutXmlDeclaration("<?xml version=""1.0"" encoding=""UTF-8""?>" & vbCrLf & "<ossec_config/>")
  If InStr(text,"<?xml")>0 Or Left(text,1)=ChrW(-257) Then Err.Raise 513,,"XML declaration removal failed"
  Set document=CreateObject("Msxml2.DOMDocument.3.0")
  document.async=False : document.resolveExternals=False
  If Not document.LoadXML(text) Then Err.Raise 513,,"Declaration-free XML failed to parse"
  fields=ParseCsv("""WazuhPasswordAudit"",""cscript.exe """"C:\Program Files\test.vbs""""""")
  If UBound(fields)<>1 Then Err.Raise 513,,"CSV field count failed"
  If fields(0)<>"WazuhPasswordAudit" Then Err.Raise 513,,"CSV task name failed"
  If fields(1)<>"cscript.exe ""C:\Program Files\test.vbs""" Then Err.Raise 513,,"CSV quote decoding failed"
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
  WScript.Echo "XP bootstrap pure self-tests: PASS"
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
```
