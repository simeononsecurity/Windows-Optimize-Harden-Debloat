#Opt-out nVidia telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID44231 -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID64640 -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID66610 -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" -Name OptInOrOutPreference -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" -Name Start -Type REG_DWORD -Value 4 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\Startup\SendTelemetryData" -Name 0 -Type REG_DWORD -Value 0 -Force
sc stop NvTelemetryContainer
sc config NvTelemetryContainer start=disabled
schtasks /change -TypeN NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} -Valueisable
schtasks /change -TypeN NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} -Valueisable
schtasks /change -TypeN NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} -Valueisable
schtasks /change -TypeN NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} -Valueisable

#Disable Razer Game Scanner service
sc stop "Razer Game Scanner Service"
sc config "Razer Game Scanner Service" start=disabled

#Disable Game Bar features
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name AllowgameDVR -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type REG_DWORD -Value 0 -Force

#Disable Logitech Gaming service
sc stop "LogiRegistryService"
sc config "LogiRegistryService" start=disabled

#Disable Visual Studio telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM" -Name OptIn -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Type REG_DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type REG_DWORD -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type REG_DWORD -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name TurnOffSwitch -Type REG_DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name DisableFeedbackDialog -Type REG_DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name DisableEmailInput -Type REG_DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name DisableScreenshotCapture -Type REG_DWORD -Value 1 -Force
sc stop "VSStandardCollectorService150"
Run net stop "VSStandardCollectorService150"
sc config "VSStandardCollectorService150" start=disabled

#Block Google Chrome Software Reporter Tool
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type REG_SZ -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type REG_SZ -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name Debugger -Type REG_SZ -Value "%windir%\System32\taskkill.exe" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type REG_SZ -Value 0 -Force

#Disable storing sensitive data in Acrobat Reader DC
Set-ItemProperty -Path "HKCU:\Software\Adobe\Adobe ARM\1.0\ARM" -Name "iCheck" -Type REG_SZ -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "cSharePoint" -Type REG_SZ -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeDocumentServices" -Type REG_SZ -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeSign" -Type REG_SZ -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bTogglePrefSync" -Type REG_SZ -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleWebConnectors" -Type REG_SZ -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bAdobeSendPluginToggle" -Type REG_SZ -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bUpdater" -Type REG_SZ -Value 0 -Force

#Disable CCleaner Health Check
TASKKILL /f ccleaner.exe
TASKKILL /f ccleaner64.exe
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HomeScreen" -Type REG_SZ -Value 2 -Force

#Disable CCleaner Monitoring && more
TASKKILL /f /fI "IMAGENAME eq CCleaner*"
schtasks /Change -TypeN "CCleaner Update" -Valueisable
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "Monitoring" -Type REG_SZ -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HelpImproveCCleaner" -Type REG_SZ -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "SystemMonitoring" -Type REG_SZ -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "SystemMonitoringRunningNotification" -Type REG_SZ -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateAuto" -Type REG_SZ -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateCheck" -Type REG_SZ -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "CheckTrialOffer" -Type REG_SZ -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)GetIpmForTrial" -Type REG_SZ -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdater" -Type REG_SZ -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdaterIpm" -Type REG_SZ -Value 0 -Force

#Disable Dropbox Update service
sc config dbupdate start=disabled
sc config dbupdatem start=disabled
schtasks /Change -TypeN "DropboxUpdateTaskMachineCore" -Valueisable
schtasks /Change -TypeN "DropboxUpdateTaskMachineUA" -Valueisable

#Disable Google update service
schtasks /Change -TypeN "GoogleUpdateTaskMachineCore" -Valueisable
schtasks /Change -TypeN "GoogleUpdateTaskMachineUA" -Valueisable

#Disable Media Player telemetry
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type REG_DWORD -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type REG_DWORD -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type REG_DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type REG_DWORD -Value 1 -Force
sc config WMPNetworkSvc start=disabled

#Disable Microsoft Office telemetry
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name "Enablelogging" -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name "EnableUpload" -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -Type REG_DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Type REG_DWORD -Value 0 -Force

#Disable Microsoft Windows Live ID service
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\wlidsvc" -Name Start -Type REG_DWORD -Value 4 -Force
sc config wlidsvc start=disabled

#Disable Mozilla Firefox telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableTelemetry" -Type REG_DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableDefaultBrowserAgent" -Type REG_DWORD -Value 1 -Force

#Remove Windows Bloatware
powershell -command "Get-AppxPackage -allusers *xing* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.XboxApp* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.GamingApp* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.BingWeather* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft3DViewer* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Twitter* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.Getstarted* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Office.Sway* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *spotify* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *bingsports* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.SkypeApp* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *WindowsScan* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.Print3D* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *CommsPhone* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.Messaging* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *empires* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *microsoft.windowscommunicationsapps* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.ZuneMusic* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.WindowsMaps* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.3dbuilder* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft3DViewer* |  Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *AdobeSystemsIncorporated.AdobePhotoshopExpress* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.WindowsAlarms* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.Appconnector* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.YourPhone* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.Asphalt8Airborne* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *candycrush* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *DolbyLaboratories.DolbyAccess* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.DrawboardPDF* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Facebook* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *FarmHeroesSaga* | Remove-AppxPackage -AllUsers",
powershell -command "Get-AppxPackage -allusers *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.XboxGamingOverlay* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.GetHelp* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.BingNews* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Todos* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.Whiteboard* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *ConnectivityStore* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *MinecraftUWP* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.MixedReality.Portal* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.OneConnect* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.ZuneVideo* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Netflix* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *OneNote* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *Microsoft.MSPaint* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *PandoraMediaInc* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *CommsPhone* | Remove-AppxPackage -AllUsers"
powershell -command "Get-AppxPackage -allusers *windowsphone* | Remove-AppxPackage -AllUsers"










