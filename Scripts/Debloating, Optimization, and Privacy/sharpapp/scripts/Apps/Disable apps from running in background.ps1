### Disable apps from running in background ###
### Disabling this function means, Windows 10 apps have no more permission to run in the background so they can't update their live tiles, fetch new data, and receive notifications.
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name GlobalUserDisabled -Type DWord -Value 1 -Force