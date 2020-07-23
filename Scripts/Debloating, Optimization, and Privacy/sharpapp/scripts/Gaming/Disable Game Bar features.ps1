### Disable Game Bar features ###
### The Game DVR is a feature of the Xbox app that lets you use the Game bar (Win+G) to record and share game clips and screenshots in Windows 10. However, you can also use the Game bar to record videos and take screenshots of any app in Windows 10. ###
### This Policy will disable the Windows Game Recording and Broadcasting.
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0 -Force