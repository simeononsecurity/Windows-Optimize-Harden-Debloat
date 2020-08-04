takeown /f %windir%\Policydefinitions /r /a
icacls %windir%\PolicyDefinitions /grant Administrators:(OI)(CI)F /t
start-job -ScriptBlock {copy-item -Path .\Files\PolicyDefinitions\* -Destination C:\Windows\PolicyDefinitions -Force -Recurse -ErrorAction SilentlyContinue}
