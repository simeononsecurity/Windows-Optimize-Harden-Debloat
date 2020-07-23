### Disable Windows Tips ###
### Microsoft uses diagnostic information to determine which tips are appropriate. If you enable this policy, you will no longer see Windows Tips, e.g. Spotlight and Consumer Features, Feedback Notifications etc.
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Type DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeature" -Type DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1 -Force
