### Disable Location tracking ###
### When Location Tracking is turned on, Windows and its apps are allowed to detect the current location of your computer or device. ###
### This can be used to pinpoint your exact location, e.g. Map traces the location of PC and helps you in exploring nearby restaurants.
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny" -Force