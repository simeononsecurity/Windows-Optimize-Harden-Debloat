#Install PowerShell Modules
copy-item -Path .\Files\"PowerShell Modules"\* -Destination C:\Windows\System32\WindowsPowerShell\v1.0\Modules -Force -Recurse
#Unblock New PowerShell Modules
Get-ChildItem C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PowerSTIG\ -recurse | Unblock-File
Get-ChildItem C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\ -recurse | Unblock-File
Get-ChildItem C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PowerShellAccessControl\ -recurse | Unblock-File
#Import New PowerShell Modules
Import-Module -Name PowerSTIG -Force -Global
Import-Module -Name PSWindowsUpdate -Force -Global
Import-Module -Name PowerShellAccessControl -Force -Global
