# `launch-setup.vbs`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/launch-setup.vbs). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Запускаем deploy-windows.ps1 с повышением прав и независимым ранним журналом, ожидаем exit code и открываем итоговый TXT.

**Применение.** Для нового АРМ запускаем файл из подготовленного комплекта Windows 7/10/11. Подтверждаем штатный UAC.

**Особенности.** Пароль администратора в сценарии отсутствует. Журнал создаётся в TEMP до запуска bootstrap; stdout/stderr и коды ошибок сохраняются. Read-only DVD не скрывает раннюю ошибку. Источник VBS — UTF-16LE с BOM.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-16 с BOM. **Объём:** 640 строк.

**SHA256 оригинала:** `c5dafbb71ff62527a502731f49f15dc48dcb687cee28f8672458e271741dc0be`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```vbscript
Option Explicit



' Запускаем фиксированный bootstrap с повышением прав и сохраняем первую ошибку до MSI.



' Журнал создаём в TEMP до проверки PowerShell; DVD/HGFS может быть только для чтения.



' Пароли и ключи не передаём в аргументах, глобальную ExecutionPolicy не меняем.



If WScript.Arguments.Named.Exists("syntaxcheck") Then



  WScript.Echo "Launcher syntax: PASS"



  WScript.Quit 0



End If



If WScript.Arguments.Named.Exists("selftest") Then



  SelfTest



  WScript.Quit 0



End If



Dim fs, sh, app, service, item, version, folder, script, powershell, arguments, rc



Dim logFolder, reportPath, stdoutPath, stderrPath, status, errorCode, errorText, started



Set fs=CreateObject("Scripting.FileSystemObject")



Set sh=CreateObject("WScript.Shell")



folder=fs.GetParentFolderName(WScript.ScriptFullName)



script=fs.BuildPath(folder,"deploy-windows.ps1")



started=CStr(Now) : status="starting" : rc=-1 : version=""



logFolder=GetLogFolder()



reportPath=fs.BuildPath(logFolder,"setup-result.txt")



stdoutPath=fs.BuildPath(logFolder,"stdout.log")



stderrPath=fs.BuildPath(logFolder,"stderr.log")



' Даже если PowerShell не сможет разобрать файл, этот первый отчёт уже существует.



WriteReport ""



On Error Resume Next



RunSetup



errorCode=Err.Number : errorText=Err.Description : Err.Clear



On Error GoTo 0



If errorCode<>0 Then



  status="launcher_error"



  WriteReport "Launcher error: " & CStr(errorCode) & " " & RedactText(errorText)



Else



  WriteReport ""



End If



If status<>"elevation_requested" Then



  ' Показываем только итоговый текстовый журнал, а не окно терминала.



  On Error Resume Next



  sh.Run Quote(sh.ExpandEnvironmentStrings("%SystemRoot%\System32\notepad.exe")) & " " & Quote(reportPath),1,False



  On Error GoTo 0



End If



If errorCode<>0 Then WScript.Quit 1



If status="elevation_requested" Then WScript.Quit 0



WScript.Quit rc







Sub RunSetup



  Dim command, output, errors



  Set service=GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")



  For Each item In service.ExecQuery("SELECT Version FROM Win32_OperatingSystem")



    version=item.Version



  Next



  If Len(version)=0 Then Err.Raise 513,,"Cannot determine the Windows version."



  If CLng(Split(version,".")(0))<6 Then Err.Raise 513,,"Windows XP uses the separate deploy-xp.vbs procedure."



  If Not fs.FileExists(script) Then Err.Raise 513,,"Missing deploy-windows.ps1 beside this launcher."



  powershell=sh.ExpandEnvironmentStrings("%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe")



  If fs.FileExists(sh.ExpandEnvironmentStrings("%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe")) Then powershell=sh.ExpandEnvironmentStrings("%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe")



  If Not fs.FileExists(powershell) Then Err.Raise 513,,"Windows PowerShell is not available."



  WriteReport ""



  If Not WScript.Arguments.Named.Exists("elevated") Then



    ' Повышаем сам launcher: затем он может ждать процесс и записать его exit code/stderr.



    Set app=CreateObject("Shell.Application")



    arguments=Quote(WScript.ScriptFullName) & " /elevated /logdir:" & Quote(logFolder)



    app.ShellExecute WScript.FullName,arguments,folder,"runas",0



    status="elevation_requested"



    Exit Sub



  End If



  status="running" : WriteReport ""



  ' Команда фиксирована: только наш PS1, порог60 и процессная ExecutionPolicy Bypass.



  ' UTF-8 для stdout/stderr задаём до разбора PS1, чтобы прочитать локализованную первую ошибку.



  arguments=BuildPowerShellArguments(script)



  command=Quote(powershell) & " " & arguments & " 1>" & Quote(stdoutPath) & " 2>" & Quote(stderrPath)



  rc=sh.Run(Quote(sh.ExpandEnvironmentStrings("%SystemRoot%\System32\cmd.exe")) & " /d /s /c " & Quote(command),0,True)



  output=RedactText(ReadUtf8IfExists(stdoutPath))



  errors=RedactText(ReadUtf8IfExists(stderrPath))



  ' Сохраняем уже очищенный текст и в отдельных потоковых журналах.



  WriteUtf8 stdoutPath,output : WriteUtf8 stderrPath,errors



  status="finished"



  If rc<>0 Then status="bootstrap_failed_or_partial"



End Sub



Function GetLogFolder()



  Dim candidate, base



  base=fs.GetAbsolutePathName(sh.ExpandEnvironmentStrings("%TEMP%"))



  candidate=""



  If WScript.Arguments.Named.Exists("logdir") Then candidate=WScript.Arguments.Named("logdir")



  If Len(candidate)>0 Then



    candidate=fs.GetAbsolutePathName(candidate)



    If LCase(Left(candidate,Len(base & "\SIEM-Setup-")))<>LCase(base & "\SIEM-Setup-") Then candidate=""



    If Len(candidate)>0 Then If Not fs.FolderExists(candidate) Then candidate=""



  End If



  If Len(candidate)=0 Then



    candidate=fs.BuildPath(base,"SIEM-Setup-" & fs.GetTempName)



    fs.CreateFolder candidate



  End If



  GetLogFolder=candidate



End Function



Sub WriteReport(extra)



  Dim output



  Set output=fs.CreateTextFile(reportPath,True,True)



  output.WriteLine "SIEM Wazuh setup - local execution report"



  output.WriteLine "Computer: " & sh.ExpandEnvironmentStrings("%COMPUTERNAME%")



  output.WriteLine "Started (local): " & started



  output.WriteLine "Updated (local): " & CStr(Now)



  output.WriteLine "OS version: " & version



  output.WriteLine "Status: " & status



  output.WriteLine "Exit code: " & CStr(rc)



  output.WriteLine "Bootstrap: " & script



  output.WriteLine "PowerShell: " & powershell



  output.WriteLine "Result directory: " & logFolder



  output.WriteLine "Passwords, account policy and agent keys are not printed by this launcher."



  If Len(extra)>0 Then output.WriteLine extra



  output.WriteLine vbCrLf & "--- stdout ---"



  output.WriteLine RedactText(ReadUtf8IfExists(stdoutPath))



  output.WriteLine vbCrLf & "--- stderr ---"



  output.WriteLine RedactText(ReadUtf8IfExists(stderrPath))



  output.WriteLine vbCrLf & "A local exit code does not confirm indexed delivery. Verify the run_id in Wazuh."



  output.Close



End Sub



Function BuildPowerShellArguments(path)



  Dim statement



  statement="[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false); & " & PsLiteral(path) & " -ThresholdDays 60; $setupOk=$?; $setupCode=$LASTEXITCODE; if (!$setupOk) { if ($setupCode) { exit $setupCode }; exit 1 }; if ($null -ne $setupCode) { exit $setupCode }"



  BuildPowerShellArguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " & Quote(statement)



End Function



Function PsLiteral(value)



  PsLiteral="'" & Replace(value,"'","''") & "'"



End Function



Function Quote(value)



  Quote=Chr(34) & value & Chr(34)



End Function



Function ReadUtf8IfExists(path)



  Dim stream



  ReadUtf8IfExists=""



  If Len(path)=0 Then Exit Function



  If Not fs.FileExists(path) Then Exit Function



  Set stream=CreateObject("ADODB.Stream")



  stream.Type=2 : stream.Charset="utf-8" : stream.Open : stream.LoadFromFile path



  ReadUtf8IfExists=stream.ReadText : stream.Close



End Function



Sub WriteUtf8(path,text)



  Dim stream



  Set stream=CreateObject("ADODB.Stream")



  stream.Type=2 : stream.Charset="utf-8" : stream.Open : stream.WriteText text



  stream.SaveToFile path,2 : stream.Close



End Sub



Function RedactText(text)



  Dim expression



  Set expression=New RegExp : expression.Global=True : expression.IgnoreCase=True



  expression.Pattern="\b[0-9a-f]{64}\b"



  text=expression.Replace(text,"[REDACTED_HEX64]")



  expression.Pattern="((password|registration_password|auth_key)\s*[:=]\s*)\S+"



  RedactText=expression.Replace(text,"$1[REDACTED]")



End Function



Sub SelfTest



  Dim text



  text=BuildPowerShellArguments("C:\Install\A'B\deploy-windows.ps1")



  If InStr(text,"A''B")=0 Then Err.Raise 513,,"PowerShell literal escaping failed."



  If InStr(text,"-ExecutionPolicy Bypass")=0 Or InStr(text,"-ThresholdDays 60")=0 Then Err.Raise 513,,"Fixed bootstrap arguments failed."



  If InStr(RedactText(String(64,"a")),String(64,"a"))>0 Then Err.Raise 513,,"Hex key redaction failed."



  If InStr(RedactText("password=secret"),"secret")>0 Then Err.Raise 513,,"Password assignment redaction failed."



  WScript.Echo "Launcher pure self-tests: PASS"



End Sub



```
