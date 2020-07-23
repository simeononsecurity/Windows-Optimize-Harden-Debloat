### Disable Timeline history ### 
### Microsoft made Timeline available to the public with Windows 10 build 17063. It collects a history of activities you've performed, including files you've opened and web pages you've viewed in Edge.
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0 -Force