# `collect-password-audit-xp.vbs`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/collect-password-audit-xp.vbs). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Получаем метаданные локальных пользователей XP через доступные старой Windows интерфейсы и записываем JSONL v2.

**Применение.** Контроль: cscript.exe //Nologo C:\SIEM-Audit\Password\collect-password-audit-xp.vbs /threshold:60. Самопроверка: /selftest.

**Особенности.** Основной сбор не меняет пароли и политику. Режим /secure отдельно настраивает ACL рабочего каталога. Общую парольную политику этот адаптер не собирает. Исполнитель из окружения является необязательной метаинформацией; файл VBS сохраняем в UTF-16LE с BOM.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-16 с BOM. **Объём:** 480 строк.

**SHA256 оригинала:** `5a9867660b5cd0c83c36a27b235bf550c080e348b7a94b8eff88417b9ba65bbd`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```vbscript
Option Explicit
' Выполняем локальный аудит метаданных учётных записей Windows XP.
' Пароли, хеши, учётные записи и парольную политику не изменяем.
' JSON записываем в ASCII; кириллицу представляем последовательностями \uXXXX.

Dim fs, sh, svc, host, rootDir, logDir, logFile, lockDir, lockOwned
Dim threshold, runId, observed, rows, expected, emitted, enabledCount
Dim knownOver, unknownCount, identityComplete, enumerationComplete, seen
Dim account, accounts, user, age, flags, expired, ageOk, flagsOk, expiredOk
Dim userName, userSid, enabled, row, rowError, errorText, code, status, summary
Dim os, version, datetime, utcNow, item, allText, sidOk

' Самопроверку выполняем до чтения ОС, создания каталогов и записи файлов.
If WScript.Arguments.Named.Exists("selftest") Then
  SelfTest
  WScript.Quit 0
End If

Set fs = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
rootDir = "C:\SIEM-Audit\Password"
logDir = rootDir & "\logs"
lockDir = rootDir & "\collector-xp.lock"
lockOwned = False

' Установщик вызывает этот режим до создания задачи с правами SYSTEM.
If WScript.Arguments.Named.Exists("secure") Then
  SecureInstallation
  WScript.Quit 0
End If

threshold = 60
If WScript.Arguments.Named.Exists("threshold") Then
  If Not IsNumeric(WScript.Arguments.Named("threshold")) Then
    WScript.Echo "Invalid threshold. Expected an integer from 1 to 36500."
    WScript.Quit 2
  End If
  threshold = CDbl(WScript.Arguments.Named("threshold"))
  If threshold < 1 Or threshold > 36500 Or threshold <> Fix(threshold) Then
    WScript.Echo "Invalid threshold. Expected an integer from 1 to 36500."
    WScript.Quit 2
  End If
End If

host = sh.ExpandEnvironmentStrings("%COMPUTERNAME%")
Set datetime = CreateObject("WbemScripting.SWbemDateTime")
datetime.SetVarDate Now, True
utcNow = datetime.GetVarDate(False)
observed = Stamp(utcNow) & "Z"
runId = host & "-" & Replace(Replace(Stamp(utcNow), ":", ""), "-", "") & "-" & fs.GetTempName
logFile = logDir & "\password-audit-" & DayKey(utcNow) & ".jsonl"
EnsureFolder rootDir
EnsureFolder logDir

expected = 0 : emitted = 0 : enabledCount = 0
knownOver = 0 : unknownCount = 0
enumerationComplete = False : identityComplete = True
allText = ""
Set seen = CreateObject("Scripting.Dictionary")
seen.CompareMode = 1

' Создание каталога выполняется атомарно. Чужой lock автоматически не удаляем:
' на XP нельзя считать время надёжным доказательством завершения процесса.
On Error Resume Next
fs.CreateFolder lockDir
code = Err.Number : errorText = Err.Description
Err.Clear
On Error GoTo 0
If code <> 0 Then Fail "Collector lock exists or cannot be created: " & errorText
lockOwned = True

On Error Resume Next
Set svc = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
code = Err.Number : errorText = Err.Description
Err.Clear
On Error GoTo 0
If code <> 0 Then Fail "WMI connection failed: " & errorText

version = ""
On Error Resume Next
For Each os In svc.ExecQuery("SELECT Version FROM Win32_OperatingSystem")
  version = os.Version
Next
code = Err.Number : errorText = Err.Description
Err.Clear
On Error GoTo 0
If code <> 0 Then Fail "OS detection failed: " & errorText
If Left(version, 3) <> "5.1" Then Fail "This collector is restricted to Windows XP (5.1)."

' Перечисляем только локальные обычные пользовательские учётные записи.
On Error Resume Next
Set accounts = svc.ExecQuery("SELECT Name,SID,Disabled FROM Win32_UserAccount WHERE LocalAccount=True AND AccountType=512")
code = Err.Number : errorText = Err.Description
Err.Clear
On Error GoTo 0
If code <> 0 Then Fail "Account enumeration failed: " & errorText

enumerationComplete = True
On Error Resume Next
For Each account In accounts
  userName = "" : userSid = "" : enabled = False
  userName = account.Name
  userSid = account.SID
  enabled = Not account.Disabled
  code = Err.Number : errorText = Err.Description
  Err.Clear
  If code <> 0 Then
    enumerationComplete = False
    Exit For
  End If
  expected = expected + 1
  CollectUser userName, userSid, enabled
Next
If Err.Number <> 0 Then
  enumerationComplete = False
  errorText = Err.Description
End If
Err.Clear
On Error GoTo 0

status = "ok"
If unknownCount > 0 Or Not identityComplete Then status = "partial"
If Not enumerationComplete Then
  status = "error"
  identityComplete = False
End If
summary = Header("summary")
summary = summary & ExecutorMetadataJson()
summary = summary & ",""collection_status"":" & J(status)
summary = summary & ",""enumeration_complete"":" & Bool(enumerationComplete)
summary = summary & ",""identity_complete"":" & Bool(identityComplete)
If enumerationComplete Then summary = summary & ",""expected_user_count"":" & CStr(expected)
summary = summary & ",""emitted_user_count"":" & CStr(emitted)
summary = summary & ",""known_enabled_count"":" & CStr(enabledCount)
If enumerationComplete Then summary = summary & ",""enabled_count"":" & CStr(enabledCount)
summary = summary & ",""known_over_threshold_count"":" & CStr(knownOver)
summary = summary & ",""unknown_count"":" & CStr(unknownCount)
' Точный итог публикуем только после полного сбора всех необходимых значений.
If enumerationComplete And identityComplete And unknownCount = 0 Then
  summary = summary & ",""over_threshold_count"":" & CStr(knownOver)
End If
If Not enumerationComplete Then summary = summary & ",""read_error"":" & J(errorText)
allText = allText & summary & "}}" & vbCrLf
WriteBatch allText
ReleaseLock
WScript.Echo "Password audit written to " & logFile
If status = "error" Then WScript.Quit 1
If status = "partial" Then WScript.Quit 3
WScript.Quit 0

Sub CollectUser(name, sid, isEnabled)
  Dim localUser, localAge, localFlags, localExpired, aOk, fOk, eOk, text, errInfo, rowStatus
  If isEnabled Then enabledCount = enabledCount + 1
  sidOk = Len(sid) > 0
  If sidOk Then
    If seen.Exists(sid) Then sidOk = False
  End If
  If Not sidOk Then identityComplete = False
  If Len(sid) > 0 And Not seen.Exists(sid) Then seen.Add sid, True
  Set localUser = Nothing
  errInfo = ""
  On Error Resume Next
  Set localUser = GetObject("WinNT://" & host & "/" & name & ",user")
  If Err.Number <> 0 Then errInfo = "WinNT bind: " & CStr(Err.Number) & " " & Err.Description
  Err.Clear
  On Error GoTo 0
  aOk = False : fOk = False : eOk = False
  If Not localUser Is Nothing Then
    localAge = ReadProperty(localUser, "PasswordAge", aOk)
    localFlags = ReadProperty(localUser, "UserFlags", fOk)
    localExpired = ReadProperty(localUser, "PasswordExpired", eOk)
  End If
  If Not IsNumeric(localAge) Then aOk = False
  If aOk Then
    If CDbl(localAge) < 0 Then aOk = False
  End If
  If Not IsNumeric(localFlags) Then fOk = False
  If Not IsNumeric(localExpired) Then eOk = False
  rowStatus = "ok"
  If Not aOk Or Not fOk Or Not eOk Or Not sidOk Then rowStatus = "partial"
  If localUser Is Nothing Then rowStatus = "error"
  If rowStatus <> "ok" Then
    unknownCount = unknownCount + 1
    If Len(errInfo) = 0 Then errInfo = "One or more properties or SID could not be read."
  End If
  text = Header("user") & ",""username"":" & J(name)
  If Len(sid) > 0 Then text = text & ",""sid"":" & J(sid)
  text = text & ",""enabled"":" & Bool(isEnabled)
  If aOk Then
    text = text & ",""age_seconds"":" & CStr(Fix(CDbl(localAge)))
    text = text & ",""age_days"":" & CStr(Int(CDbl(localAge) / 86400))
    text = text & ",""threshold_exceeded"":" & Bool(AgeExceeds(CDbl(localAge), threshold))
    If isEnabled And AgeExceeds(CDbl(localAge), threshold) Then knownOver = knownOver + 1
  End If
  If fOk Then text = text & ",""never_expires"":" & Bool((CLng(localFlags) And 65536) <> 0)
  If eOk Then text = text & ",""expired_reported"":" & Bool(CLng(localExpired) <> 0)
  text = text & ",""collection_status"":" & J(rowStatus)
  If Len(errInfo) > 0 Then text = text & ",""read_error"":" & J(errInfo)
  allText = allText & text & "}}" & vbCrLf
  emitted = emitted + 1
End Sub

Function Header(kind)
  Header = "{""password_audit_v2"":{""schema_version"":2,""collector_version"":""2.0.0"",""kind"":" & J(kind)
  Header = Header & ",""computer"":" & J(host) & ",""run_id"":" & J(runId)
  Header = Header & ",""observed_at_utc"":" & J(observed) & ",""scope"":""local_sam_metadata"",""threshold_days"":" & CStr(threshold)
  ' Локальную максимальную длительность в XP-адаптере не определяем.
  ' Не подменяем неизвестное значение нулём или признаком бессрочности.
  Header = Header & ",""policy_read_status"":""not_collected"""
End Function

Sub WriteBatch(text)
  Dim output, ioCode, ioError
  On Error Resume Next
  Set output = fs.OpenTextFile(logFile, 8, True, False)
  ioCode = Err.Number : ioError = Err.Description
  Err.Clear
  If ioCode = 0 Then
    output.Write text
    ioCode = Err.Number : ioError = Err.Description
    Err.Clear
    output.Close
    If Err.Number <> 0 Then
      ioCode = Err.Number : ioError = Err.Description
    End If
  End If
  Err.Clear
  On Error GoTo 0
  If ioCode <> 0 Then
    ReleaseLock
    WScript.Echo "JSONL write failed: " & ioError
    WScript.Quit 4
  End If
End Sub

Sub Fail(message)
  Dim failure
  failure = Header("summary") & ",""collection_status"":""error"",""enumeration_complete"":false,""identity_complete"":false,""emitted_user_count"":" & CStr(emitted) & ",""read_error"":" & J(message) & "}}" & vbCrLf
  WriteBatch failure
  ReleaseLock
  WScript.Echo message
  WScript.Quit 1
End Sub

Sub ReleaseLock
  If lockOwned Then
    On Error Resume Next
    fs.DeleteFolder lockDir, False
    Err.Clear
    On Error GoTo 0
    lockOwned = False
  End If
End Sub

Sub EnsureFolder(path)
  Dim parent
  If fs.FolderExists(path) Then Exit Sub
  parent = fs.GetParentFolderName(path)
  If Len(parent) > 0 And Not fs.FolderExists(parent) Then EnsureFolder parent
  fs.CreateFolder path
End Sub

Function ReadProperty(obj, prop, ByRef ok)
  On Error Resume Next
  Err.Clear
  ReadProperty = obj.Get(prop)
  ok = Err.Number = 0
  Err.Clear
  On Error GoTo 0
End Function

' Это заявленные значения окружения процесса, а не аттестация security token.
' Локализованное имя SYSTEM получаем по неизменному SID S-1-5-18.
Function ExecutorMetadataJson()
  Dim environment,userName,domainName,systemName,systemDomain,systemAccount,known,declared,result
  userName="" : domainName="" : systemName="" : systemDomain=""
  On Error Resume Next
  Set environment=sh.Environment("PROCESS")
  userName=environment("USERNAME") : domainName=environment("USERDOMAIN")
  If Err.Number<>0 Then userName="" : domainName=""
  Err.Clear
  Set systemAccount=svc.Get("Win32_SID.SID='S-1-5-18'")
  If Err.Number=0 Then
    systemName=systemAccount.AccountName : systemDomain=systemAccount.ReferencedDomainName
  End If
  Err.Clear : On Error GoTo 0
  result=",""executor_identity_source"":""process_environment"",""executor_account"":"
  If Len(userName)>0 And Len(domainName)>0 Then
    result=result & J(domainName & "\" & userName)
  Else
    result=result & "null"
  End If
  declared=DeclaredSystemAccount(userName,domainName,systemName,systemDomain)
  result=result & ",""executor_is_system"":"
  If IsNull(declared) Then result=result & "null" Else result=result & Bool(declared)
  ExecutorMetadataJson=result
End Function
Function DeclaredSystemAccount(userName,domainName,systemName,systemDomain)
  DeclaredSystemAccount=Null
  If Len(userName)=0 Or Len(domainName)=0 Or Len(systemName)=0 Or Len(systemDomain)=0 Then Exit Function
  DeclaredSystemAccount=(LCase(userName)=LCase(systemName) And LCase(domainName)=LCase(systemDomain))
End Function

Function AgeExceeds(seconds, days)
  AgeExceeds = CDbl(seconds) > CDbl(days) * 86400
End Function

Function Bool(value)
  If value Then Bool = "true" Else Bool = "false"
End Function

Function Stamp(value)
  Stamp = Year(value) & "-" & Right("0" & Month(value), 2) & "-" & Right("0" & Day(value), 2) & "T" & Right("0" & Hour(value), 2) & ":" & Right("0" & Minute(value), 2) & ":" & Right("0" & Second(value), 2)
End Function

Function DayKey(value)
  DayKey = Year(value) & Right("0" & Month(value), 2) & Right("0" & Day(value), 2)
End Function

Function J(value)
  Dim result, i, ch, n
  result = Chr(34)
  For i = 1 To Len(CStr(value))
    ch = Mid(CStr(value), i, 1)
    n = AscW(ch)
    If n < 0 Then n = n + 65536
    If n = 34 Or n = 92 Then
      result = result & Chr(92) & ch
    ElseIf n < 32 Or n > 126 Then
      result = result & Chr(92) & "u" & Right("0000" & Hex(n), 4)
    Else
      result = result & ch
    End If
  Next
  J = result & Chr(34)
End Function

' Установочный режим: защищаем предка и выделенный каталог комплекта.
' Владельцем назначаем SYSTEM. После каждого изменения проверяем owner и DACL.
' При отсутствии привилегий или несовпадении результата задача не создаётся.
Sub SecureInstallation
  Dim service, osCheck, xpVersion, parentDir, parentObject
  If LCase(fs.GetParentFolderName(WScript.ScriptFullName)) <> LCase(rootDir) Then
    WScript.Echo "Place the collector in " & rootDir & " before applying permissions."
    WScript.Quit 5
  End If
  Set service = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
  xpVersion = ""
  For Each osCheck In service.ExecQuery("SELECT Version FROM Win32_OperatingSystem")
    xpVersion = osCheck.Version
  Next
  If Left(xpVersion, 3) <> "5.1" Then
    WScript.Echo "This installer is restricted to Windows XP (5.1)."
    WScript.Quit 5
  End If

  ' Включаем привилегии изменения владельца. Ошибки не подавляем.
  service.Security_.Privileges.AddAsString "SeRestorePrivilege", True
  service.Security_.Privileges.AddAsString "SeTakeOwnershipPrivilege", True

  parentDir = fs.GetParentFolderName(rootDir)
  If LCase(parentDir) <> "c:\siem-audit" Then Err.Raise 513, , "Unexpected installation parent."
  Set parentObject = fs.GetFolder(parentDir)
  RejectReparse parentObject
  RejectReparse fs.GetFolder(rootDir)

  ' Защищаем только самого предка. ACL корня C:\ и других его каталогов не меняем.
  ' В чужие подкаталоги C:\SIEM-Audit не переходим.
  SecureObject service, parentObject, True, False
  SecureObject service, fs.GetFolder(rootDir), True, True
  EnsureFolder logDir
  SecureObject service, fs.GetFolder(logDir), True, True
  WScript.Echo "ACL and owner verified: SYSTEM and local Administrators only."
End Sub

Sub RejectReparse(obj)
  If (obj.Attributes And 1024) <> 0 Then Err.Raise 513, , "Reparse points are not supported: " & obj.Path
End Sub

Sub SecureObject(service, obj, isFolder, recursive)
  Dim setting, sd, adminAce, systemAce, ownerTrustee, rc, child, path
  RejectReparse obj
  path = Replace(obj.Path, "\", "\\")
  Set setting = service.Get("Win32_LogicalFileSecuritySetting.Path=" & Chr(34) & path & Chr(34))
  Set sd = service.Get("Win32_SecurityDescriptor").SpawnInstance_
  sd.ControlFlags = 4100
  Set ownerTrustee = TrusteeForSid(service, "S-1-5-18")
  sd.Owner = ownerTrustee
  Set systemAce = FullAce(service, "S-1-5-18", isFolder)
  Set adminAce = FullAce(service, "S-1-5-32-544", isFolder)
  sd.DACL = Array(systemAce, adminAce)
  rc = setting.SetSecurityDescriptor(sd)
  If rc <> 0 Then Err.Raise 513, , "SetSecurityDescriptor returned " & rc & ": " & obj.Path
  VerifySecurity service, setting, isFolder, obj.Path
  If isFolder And recursive Then
    For Each child In obj.Files
      SecureObject service, child, False, False
    Next
    For Each child In obj.SubFolders
      SecureObject service, child, True, True
    Next
  End If
End Sub

Sub VerifySecurity(service, setting, isFolder, path)
  Dim actual, rc, systemSid, adminSid, ace, count, seenSystem, seenAdmin, expectedFlags
  rc = setting.GetSecurityDescriptor(actual)
  If rc <> 0 Then Err.Raise 513, , "GetSecurityDescriptor returned " & rc & ": " & path
  Set systemSid = service.Get("Win32_SID.SID=" & Chr(34) & "S-1-5-18" & Chr(34))
  Set adminSid = service.Get("Win32_SID.SID=" & Chr(34) & "S-1-5-32-544" & Chr(34))
  If Not EqualBytes(actual.Owner.SID, systemSid.BinaryRepresentation) Then Err.Raise 513, , "Unexpected owner after ACL update: " & path
  If (actual.ControlFlags And 4096) = 0 Then Err.Raise 513, , "DACL inheritance remains enabled: " & path
  If Not IsArray(actual.DACL) Then Err.Raise 513, , "DACL is absent: " & path
  count = 0 : seenSystem = False : seenAdmin = False
  expectedFlags = 0
  If isFolder Then expectedFlags = 3
  For Each ace In actual.DACL
    count = count + 1
    If ace.AceType <> 0 Then Err.Raise 513, , "Unexpected ACE type: " & path
    If ace.AccessMask <> 2032127 Then Err.Raise 513, , "Unexpected access mask: " & path
    If ace.AceFlags <> expectedFlags Then Err.Raise 513, , "Unexpected ACE inheritance flags: " & path
    If EqualBytes(ace.Trustee.SID, systemSid.BinaryRepresentation) Then
      If seenSystem Then Err.Raise 513, , "Duplicate SYSTEM ACE: " & path
      seenSystem = True
    ElseIf EqualBytes(ace.Trustee.SID, adminSid.BinaryRepresentation) Then
      If seenAdmin Then Err.Raise 513, , "Duplicate Administrators ACE: " & path
      seenAdmin = True
    Else
      Err.Raise 513, , "Unexpected trustee: " & path
    End If
  Next
  If count <> 2 Or Not seenSystem Or Not seenAdmin Then Err.Raise 513, , "Incomplete protected DACL: " & path
End Sub

Function TrusteeForSid(service, sid)
  Dim trustee, sidObject
  Set sidObject = service.Get("Win32_SID.SID=" & Chr(34) & sid & Chr(34))
  Set trustee = service.Get("Win32_Trustee").SpawnInstance_
  trustee.SID = sidObject.BinaryRepresentation
  trustee.SIDString = sid
  Set TrusteeForSid = trustee
End Function

Function FullAce(service, sid, isFolder)
  Dim trustee, ace
  Set trustee = TrusteeForSid(service, sid)
  Set ace = service.Get("Win32_ACE").SpawnInstance_
  ace.AccessMask = 2032127
  ace.AceType = 0
  If isFolder Then ace.AceFlags = 3 Else ace.AceFlags = 0
  ace.Trustee = trustee
  Set FullAce = ace
End Function

Function EqualBytes(leftBytes, rightBytes)
  Dim i
  EqualBytes = False
  If Not IsArray(leftBytes) Or Not IsArray(rightBytes) Then Exit Function
  If UBound(leftBytes) - LBound(leftBytes) <> UBound(rightBytes) - LBound(rightBytes) Then Exit Function
  For i = 0 To UBound(leftBytes) - LBound(leftBytes)
    If leftBytes(LBound(leftBytes) + i) <> rightBytes(LBound(rightBytes) + i) Then Exit Function
  Next
  EqualBytes = True
End Function

Sub SelfTest
  If AgeExceeds(60 * 86400, 60) Then Err.Raise 513, , "Exact threshold boundary failed"
  If Not AgeExceeds(60 * 86400 + 1, 60) Then Err.Raise 513, , "Threshold plus one second failed"
  If AgeExceeds(59 * 86400, 60) Then Err.Raise 513, , "Below threshold failed"
  If Bool(False) <> "false" Or Bool(True) <> "true" Then Err.Raise 513, , "Boolean JSON failed"
  If J(ChrW(1040)) <> Chr(34) & "\u0410" & Chr(34) Then Err.Raise 513, , "Cyrillic JSON failed"
  If J("a" & Chr(34) & "\") <> Chr(34) & "a\" & Chr(34) & "\\" & Chr(34) Then Err.Raise 513, , "Escaping failed"
  If DayKey(DateSerial(2026, 1, 2)) <> "20260102" Then Err.Raise 513, , "Day key failed"
  If Not EqualBytes(Array(1, 2, 3), Array(1, 2, 3)) Then Err.Raise 513, , "SID byte equality failed"
  If EqualBytes(Array(1, 2, 3), Array(1, 2, 4)) Then Err.Raise 513, , "SID byte inequality failed"
  If Not IsNull(DeclaredSystemAccount("","","SYSTEM","NT AUTHORITY")) Then Err.Raise 513,,"Unknown executor must remain null."
  If Not DeclaredSystemAccount("SYSTEM","NT AUTHORITY","SYSTEM","NT AUTHORITY") Then Err.Raise 513,,"Declared SYSTEM metadata failed."
  If DeclaredSystemAccount("Admin","PC","SYSTEM","NT AUTHORITY") Then Err.Raise 513,,"Ordinary user declared SYSTEM."
  WScript.Echo "XP collector pure self-tests: PASS"
End Sub
```
