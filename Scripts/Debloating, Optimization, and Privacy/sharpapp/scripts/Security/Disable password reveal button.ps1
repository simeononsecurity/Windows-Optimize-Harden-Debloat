### Disable password reveal button ###
### On the new login screen, Microsoft added a password review button that displays what's in the password box in plain text when pressed. Note that, disabling Password Reveal button disables this feature not only in login screen but also in Microsoft Edge, Internet Explorer as well. ###
### Visible passwords may be seen by nearby persons, compromising them. The password reveal button can be used to display an entered password and should be disabled with this policy.
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Type DWord -Value 1 -Force
