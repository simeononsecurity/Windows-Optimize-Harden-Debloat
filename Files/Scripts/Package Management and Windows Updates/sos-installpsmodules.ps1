#Install PowerShell Modules
start-job -ScriptBlock {copy-item -Path .\Files\"PowerShell Modules"\*  -Destination C:\Windows\System32\WindowsPowerShell\v1.0\Modules -Force -Recurse -ErrorAction SilentlyContinue}
#Unblock New PowerShell Modules
start-job -ScriptBlock {Unblock-File -Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PowerSTIG\"; Unblock-File -Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\"; Unblock-File -Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PowerShellAccessControl\"}
#Import New PowerShell Modules
start-job -ScriptBlock {Import-Module -Name PowerSTIG -Force -Global; Import-Module -Name PSWindowsUpdate -Force -Global; Import-Module -Name PowerShellAccessControl -Force -Global}
