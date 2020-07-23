### Disable SmartScreen Filter ###
### SmartScreen Filter is a feature in Microsoft Edge that helps detect phishing websites. SmartScreen Filter can also help protect you from downloading or installing malware (malicious software). ###
### If Microsoft Edge won't let you download a file you know is fine, run this script to bypass the SmartScreen Filter in Windows 10.
If (!(Test-Path "HKCU:\Software\Microsoft\Edge\SmartScreenEnabled")) {
	New-Item -Path "HKCU:\Software\Microsoft\Edge\SmartScreenEnabled" -Force | Out-Null
}
New-ItemProperty -Path "HKCU:\Software\Microsoft\Edge\SmartScreenEnabled" -Type DWord -Value 1 -Force
