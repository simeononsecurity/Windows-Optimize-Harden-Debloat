#Opt-out nVidia telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID44231 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID64640 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID66610 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" -Name OptInOrOutPreference -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" -Name Start -Type DWORD -Value 4 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\Startup\SendTelemetryData" -Name 0 -Type DWORD -Value 0 -Force
Stop-Service NvTelemetryContainer
Set-Service NvTelemetryContainer -StartupType Disabled
schtasks /change /TN NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /Disable
schtasks /change /TN NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /Disable
schtasks /change /TN NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /Disable
schtasks /change /TN NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /Disable

#Disable Razer Game Scanner service
Stop-Service "Razer Game Scanner Service"
Set-Service "Razer Game Scanner Service" -StartupType Disabled

#Disable Game Bar features
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name AllowgameDVR -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type DWORD -Value 0 -Force

#Disable Logitech Gaming service
Stop-Service "LogiRegistryService"
Set-Service "LogiRegistryService" -StartupType Disabled

#Disable Visual Studio telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM" -Name OptIn -Type DWORD -Value 0 -Force
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
Run net stop "VSStandardCollectorService150"
Set-Service "VSStandardCollectorService150" -StartupType Disabled

#Block Google Chrome Software Reporter Tool
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name Debugger -Type STRING -Value "%windir%\System32\taskkill.exe" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type STRING -Value 0 -Force

#Disable storing sensitive data in Acrobat Reader DC
Set-ItemProperty -Path "HKCU:\Software\Adobe\Adobe ARM\1.0\ARM" -Name "iCheck" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "cSharePoint" -Type STRING -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeDocumentServices" -Type STRING -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeSign" -Type STRING -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bTogglePrefSync" -Type STRING -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleWebConnectors" -Type STRING -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bAdobeSendPluginToggle" -Type STRING -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bUpdater" -Type STRING -Value 0 -Force

#Disable CCleaner Health Check
Stop-Process -Force -Name  ccleaner.exe
Stop-Process -Force -Name  ccleaner64.exe
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HomeScreen" -Type STRING -Value 2 -Force

#Disable CCleaner Monitoring && more
Stop-Process -Force -Name "IMAGENAME eq CCleaner*"
schtasks /Change /TN "CCleaner Update" /Disable
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "Monitoring" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HelpImproveCCleaner" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "SystemMonitoring" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "SystemMonitoringRunningNotification" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateAuto" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateCheck" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "CheckTrialOffer" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)GetIpmForTrial" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdater" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdaterIpm" -Type STRING -Value 0 -Force

#Disable Dropbox Update service
Set-Service dbupdate -StartupType Disabled
Set-Service dbupdatem -StartupType Disabled
schtasks /Change /TN "DropboxUpdateTaskMachineCore" /Disable
schtasks /Change /TN "DropboxUpdateTaskMachineUA" /Disable

#Disable Google update service
schtasks /Change /TN "GoogleUpdateTaskMachineCore" /Disable
schtasks /Change /TN "GoogleUpdateTaskMachineUA" /Disable

#Disable Media Player telemetry
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWORD -Value 1 -Force
Set-Service WMPNetworkSvc -StartupType Disabled

#Disable Microsoft Office telemetry
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name "Enablelogging" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name "EnableUpload" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Type DWORD -Value 0 -Force

#Disable Microsoft Windows Live ID service
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\wlidsvc" -Name Start -Type DWORD -Value 4 -Force
Set-Service wlidsvc -StartupType Disabled

#Disable Mozilla Firefox telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableTelemetry" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableDefaultBrowserAgent" -Type DWORD -Value 1 -Force

#Remove Windows Bloatware
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
Get-AppxPackage -allusers *Microsoft3DViewer* |  Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *AdobeSystemsIncorporated.AdobePhotoshopExpress* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsAlarms* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Appconnector* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.YourPhone* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Asphalt8Airborne* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *candycrush* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *DolbyLaboratories.DolbyAccess* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.DrawboardPDF* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Facebook* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *FarmHeroesSaga* | Remove-AppxPackage 
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
