### Disable Windows Error Reporting ### 
### The error reporting feature in Windows is what produces those alerts after certain program or operating system errors, prompting you to send the information about the problem to Microsoft.
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1 -Force
Get-ScheduledTask -TaskName "QueueReporting" | Disable-ScheduledTask