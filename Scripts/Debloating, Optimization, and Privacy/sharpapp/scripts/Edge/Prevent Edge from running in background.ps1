### Prevent Edge from running in background ###
### On the new Chromium version of Microsoft Edge, extensions and other services can keep the browser running in the background even after it's closed. ###
### Although this may not be an issue for most desktop PCs, it could be a problem for laptops and low-end devices as these background processes can increase battery consumption and memory usage. The background process displays an icon in the system tray and can always be closed from there. ###
### If you run enable this policy the background mode will be disabled.
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Type DWord -Value 0 -Force
