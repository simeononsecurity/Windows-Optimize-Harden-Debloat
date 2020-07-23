### Turn off Advertising ID for Relevant Ads ###
### Windows 10 comes integrated with advertising. Microsoft assigns a unique identificator to track your activity in the Microsoft Store and on UWP apps to target you with relevant ads. ###
### If someone is giving you personalized ads, it means they are tracking your data. Turn off the advertising feature from Windows 10 with this policy to stay secure.
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0 -Force