### Disable tracking of app starts ###
### Windows can personalize your Start menu based on the apps that you launch. ###
### This allows you to quickly have access to your list of Most used apps both in the Start menu and when you search your device.
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Start_TrackProgs -Type DWord -Value 0 -Force