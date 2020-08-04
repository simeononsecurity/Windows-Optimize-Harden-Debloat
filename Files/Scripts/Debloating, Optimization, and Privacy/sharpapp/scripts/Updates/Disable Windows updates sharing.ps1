### Turn off distributing updates to other computers ###
### Windows 10 lets you download updates from several sources to speed up the process of updating the operating system. ###
### If you don't want your files to be shared by others and exposing your IP address to random computers, you can apply this policy and turn this feature off. ### 
### Acceptable selections include:
### Bypass (100) 
### Group (2)
### HTTP only (0) Enabled by SharpApp!
### LAN (1)
### Simple (99)
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 0 -Force
