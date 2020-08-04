### Disable Windows Hello Biometrics ###
### Windows Hello biometrics lets you sign in to your devices, apps, online services, and networks using your face, iris, or fingerprint. With this Policy you can disable the Windows Hello Biometrics.
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Biometrics")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Biometrics" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Biometrics" -Name "Enabled" -Type DWord -Value 0 -Force

 