#https://docs.microsoft.com/en-us/windows/privacy/
#https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
#https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds_vdi-recommendations-1909
#https://docs.microsoft.com/en-us/powershell/module/smbshare/set-smbserverconfiguration?view=win10-ps
#SMB Optimizations
Write-Output "setting smb optimizations"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" DisableBandwidthThrottling -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" FileInfoCacheEntriesMax -Value 1024 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" DirectoryCacheEntriesMax -Value 1024 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" FileNotFoundCacheEntriesMax -Value 2048 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" RequireSecuritySignature -Value 256 -Force
Set-SmbServerConfiguration -EnableMultiChannel $true -Force 
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force 
Set-SmbServerConfiguration -RequireSecuritySignature $True -Force 
Set-SmbServerConfiguration -EnableSecuritySignature $True -Force 
Set-SmbServerConfiguration -EncryptData $True -Force 
Set-SmbServerConfiguration -MaxChannelPerSession 16 -Force
Set-SmbServerConfiguration -ServerHidden $False -AnnounceServer $False -Force 
Set-SmbClientConfiguration -EnableLargeMtu $true -Force
Set-SmbClientConfiguration -EnableMultiChannel $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $True -Force
Set-SmbClientConfiguration -EnableSecuritySignature $True -Force
#onedrive
Write-Output "remove onedrive automatic start"
# Remove the automatic start item for OneDrive from the default user profile registry hive
Remove-Item -Path "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\OneDrive.lnk" -Force 
Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Load HKLM\\Temp C:\\Users\\Default\\NTUSER.DAT" -Wait
Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Delete HKLM\\Temp\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run -Name OneDriveSetup -Force" -Wait
Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Unload HKLM\\Temp"
#Disable Cortana
Write-Output "disabling cortona"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowSearchToUseLocation -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name DisableWebSearch -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name ConnectedSearchUseWeb -Type DWORD -Value 0 -Force
#Disable Device Metadata Retrieval
Write-Output "Disable Device Metadata Retrieval"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name PreventDeviceMetadataFromNetwork -Type DWORD -Value 1 -Force
#Disable Find My Device
Write-Output "Disable Find My Device"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" -Name AllowFindMyDevice -Type DWORD -Value 0 -Force
#Disable Font Streaming
Write-Output "Disable Font Streaming"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnableFontProviders -Type DWORD -Value 0 -Force
#Disable Insider Preview Builds
Write-Output "Disable Insider Preview Builds"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name AllowBuildPreview -Type DWORD -Value 0 -Force
#IE Optimizations
Write-Output "IE Optimizations"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name EnabledV9 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -Name PolicyDisableGeolocation -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -Name AutoSuggest -Type String -Value no -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name AllowServicePoweredQSA -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" -Name Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\FlipAhead" -Name Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name BackgroundSyncStatus -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name AllowOnlineTips -Type DWORD -Value 0 -Force
#Restrict License Manager
Write-Output "Restrict License Manager"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LicenseManager" -Name Start -Type DWORD -Value 4 -Force
#Disable Live Tiles
Write-Output "Disable Live Tiles"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoCloudApplicationNotification -Type DWORD -Value 1 -Force
#Disable Windows Mail App
Write-Output "Disable Windows Mail App"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Mail" -Name ManualLaunchAllowed -Type DWORD -Value 0 -Force
#Disable Microsoft Account cloud authentication service
Write-Output "Disable Microsoft Account cloud authentication service"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\wlidsvc" -Name Start -Type DWORD -Value 4 -Force
#Disable Network Connection Status Indicator
#Write-Output "Disable Network Connection Status Indicator"
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name NoActiveProbe -Type DWORD -Value 1 -Force
#Disable Offline Maps
Write-Output "Disable Offline Maps"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name AutoDownloadAndUpdateMapData -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name AllowUntriggeredNetworkTrafficOnSettingsPage -Type DWORD -Value 0 -Force
#Remove Bloatware Windows Apps
Write-Output "Remove Reinstalled Apps"
#Weather App
Write-Output "removing Weather App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.BingWeather"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Money App
Write-Output "removing Money App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.BingFinance"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Sports App
Write-Output "removing Sports App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.BingSports"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Twitter App
Write-Output "removing Twitter App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"*.Twitter"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#XBOX App
Write-Output "removing XBOX App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.XboxApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Sway App
Write-Output "removing Sway App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.Office.Sway"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Onenote App
Write-Output "removing Onenote App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.Office.OneNote"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get Office App
Write-Output "removing Get Office App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.MicrosoftOfficeHub"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get Skype App 
Write-Output "removing skype App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.SkypeApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
##General VM Optimizations
#Auto Cert Update
Write-Output "Auto Cert Update"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" -Name DisableRootAutoUpdate -Type DWORD -Value 0 -Force
#Turn off Let websites provide locally relevant content by accessing my language list
Write-Output "Turn off Let websites provide locally relevant content by accessing my language list"
Set-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Type DWORD -Value 1 -Force
#Turn off Let Windows track app launches to improve Start and search results
Write-Output "Turn off Let Windows track app launches to improve Start and search results"
Set-ItemProperty -Path "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Start_TrackProgs -Type DWORD -Value 0 -Force
#Turn off Let apps use my advertising ID for experiences across apps (turning this off will reset your ID
Write-Output "Turn off Let apps use my advertising ID for experiences across apps (turning this off will reset your ID"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name DisabledByGroupPolicy -Type DWORD -Value 1 -Force
#Turn off Let websites provide locally relevant content by accessing my language list
Write-Output "Turn off Let websites provide locally relevant content by accessing my language list"
Set-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Type DWORD -Value 1 -Force
#Turn off Let apps on my other devices open apps and continue experiences on this device
Write-Output "Turn off Let apps on my other devices open apps and continue experiences on this device"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableCdp -Type DWORD -Value 1 -Force
#Turn off Location for this device
Write-Output "Turn off Location for this device"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsAccessLocation -Type DWORD -Value 2 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name DisableLocation -Type DWORD -Value 1 -Force
#Turn off Windows should ask for my feedback
Write-Output "Turn off Windows should ask for my feedback"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name DoNotShowFeedbackNotifications -Type DWORD -Value 1 -Force
#Turn Off Send your device data to Microsoft
Write-Output "Turn Off Send your device data to Microsoft"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Type DWORD -Value 0 -Force
#Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data
Write-Output "Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKEY_Current_User\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableTailoredExperiencesWithDiagnosticData -Type DWORD -Value 1 -Force
#Turn off Let apps run in the background
Write-Output "Turn off Let apps run in the background"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsRunInBackground -Type DWORD -Value 2 -Force
#Software Protection Platform
#Opt out of sending KMS client activation data to Microsoft
Write-Output "Opt out of sending KMS client activation data to Microsoft"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name NoGenTicket -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name NoAcquireGT -Type DWORD -Value 1 -Force
#Turn off Messaging cloud sync
Write-Output "Turn off Messaging cloud sync"
Set-ItemProperty -Path "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Messaging" -Name CloudServiceSyncEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name DisableSettingSync -Type DWORD -Value 2 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name DisableSettingSyncUserOverride -Type DWORD -Value 1 -Force
#Disable Teredo
#Write-Output "Disable Teredo"
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name Teredo_State -Type String -Value Disabled -Force
#Turn off Connect to suggested open hotspots and Connect to networks shared by my contacts
Write-Output "Turn off Connect to suggested open hotspots and Connect to networks shared by my contacts"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name AutoConnectAllowedOEM -Type DWORD -Value 0 -Force
#Delivery Optimization
Write-Output "Delivery Optimization"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name DODownloadMode -Type DWORD -Value 99 -Force
Get-AppxPackage -allusers *xing* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.XboxApp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.GamingApp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.BingWeather* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft3DViewer* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Twitter* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Getstarted* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Office.Sway* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *spotify* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *bingsports* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.SkypeApp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *WindowsScan* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Print3D* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *CommsPhone* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Messaging* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *empires* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *microsoft.windowscommunicationsapps* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.ZuneMusic* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsMaps* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.3dbuilder* | Remove-AppxPackage -AllUsers
Get-AppxPackage Microsoft3DViewer  Remove-AppxPackage
Get-AppxPackage -allusers *AdobeSystemsIncorporated.AdobePhotoshopExpress* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsAlarms* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Appconnector* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.YourPhone* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Asphalt8Airborne* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *candycrush* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *DolbyLaboratories.DolbyAccess* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.DrawboardPDF* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Facebook* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *FarmHeroesSaga* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.XboxGamingOverlay* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.GetHelp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.BingNews* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Todos* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Whiteboard* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *ConnectivityStore* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *MinecraftUWP* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MixedReality.Portal* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.OneConnect* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.ZuneVideo* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Netflix* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *OneNote* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MSPaint* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *PandoraMediaInc* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *CommsPhone* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *windowsphone* | Remove-AppxPackage -AllUsers
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name CortanaConsent -Type DWORD -Value 0 -Force
Get-AppxPackage *Microsoft.549981C3F5F10* | Remove-AppxPackage
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" -Type String -Value  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search and Cortana application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" -Force
Set-MpPreference -PUAProtection Enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name AUOptions -Type DWORD -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ScheduledInstallDay -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ScheduledInstallTime -Type DWORD -Value 3 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update" -Name ExcludeWUDriversInQualityUpdate -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update" -Name ExcludeWUDriversInQualityUpdate -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdates" -Name Value -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name ExcludeWUDriversInQualityUpdate -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name ExcludeWUDriversInQualityUpdate -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type String -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type String -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name Debugger -Type String -Value "%windir%\System32\taskkill.exe" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type String -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name DisableOnline -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID44231 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID64640 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID66610 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" -Name OptInOrOutPreference -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" -Name Start -Type DWORD -Value 4 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name BlockThirdPartyCookies -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name AutofillCreditCardEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name SyncDisabled -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" -Name Debugger -Type String -Value "%windir%\System32\taskkill.exe" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name BackgroundModeEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft" -Name DoNotUpdateToEdgeWithChromium -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name AllowgameDVR -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type DWORD -Value 0 -Force
Stop-Service "LogiRegistryService"
Set-Service  "LogiRegistryService" -StartupType Disabled
Stop-Service "Razer Game Scanner Service"
Set-Service  "Razer Game Scanner Service" -StartupType Disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name DisablePasswordReveal -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Adobe\Adobe ARM\1.0\ARM" -Name "iCheck" -Type String -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "cSharePoint" -Type String -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeDocumentServices" -Type String -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeSign" -Type String -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bTogglePrefSync" -Type String -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleWebConnectors" -Type String -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bAdobeSendPluginToggle" -Type String -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bUpdater" -Type String -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HomeScreen" -Type String -Value 2 -Force
schtasks /Change /TN "DropboxUpdateTaskMachineCore" /disable
schtasks /Change /TN "DropboxUpdateTaskMachineUA" /disable
schtasks /Change /TN "GoogleUpdateTaskMachineCore" /disable
schtasks /Change /TN "GoogleUpdateTaskMachineUA" /disable
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name "Enablelogging" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name "EnableUpload" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\wlidsvc" -Name Start -Type DWORD -Value 4 -Force
Set-Service  wlidsvc -StartupType Disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableTelemetry" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableDefaultBrowserAgent" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWORD -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name TurnOffSwitch -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name DisableFeedbackDialog -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name DisableEmailInput -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name DisableScreenshotCapture -Type DWORD -Value 1 -Force
Stop-Service "VSStandardCollectorService150"
net stop "VSStandardCollectorService150"
Set-Service  "VSStandardCollectorService150" -StartupType Disabled
#General Optmizations
#Delete "windows.old" folder
%SystemRoot%\System32\Cmd.exe /c Cleanmgr /sageset:65535 
%SystemRoot%\System32\Cmd.exe /c Cleanmgr /sagerun:65535

#Display full path in explorer
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name FullPath -Type DWORD -Value 1 -Force

taskkill -Force /im explorer.exe
Start-Process explorer.exe

#Make icons easier to touch in exploere
:: Needs: Windows 10 build 19592+

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name FileExplorerInTouchImprovement -Type DWORD -Value 1 -Force

:: To kill and restart explorer
taskkill -Force /im explorer.exe
Start-Process explorer.exe
#disable