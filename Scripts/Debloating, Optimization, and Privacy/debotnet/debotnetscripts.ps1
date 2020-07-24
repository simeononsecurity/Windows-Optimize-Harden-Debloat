#Opt-out nVidia telemetry
Reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID44231 /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID64640 /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID66610 /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v OptInOrOutPreference /t REG_DWORD /d 0 /f
Reg add "HKLM\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" /v Start /t REG_DWORD /d 4 /f
Reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\Startup\SendTelemetryData" /v @ /t REG_DWORD /d 0 /f
sc stop NvTelemetryContainer
sc config NvTelemetryContainer start=disabled
schtasks /change /TN NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable
schtasks /change /TN NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable
schtasks /change /TN NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable
schtasks /change /TN NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable

#Disable Razer Game Scanner service
sc stop "Razer Game Scanner Service"
sc config "Razer Game Scanner Service" start=disabled

#Disable Game Bar features
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowgameDVR /t REG_DWORD /d 0 /f
Reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v  HistoricalCaptureEnabled /t REG_DWORD /d 0 /f

#Disable Logitech Gaming service
sc stop "LogiRegistryService"
sc config "LogiRegistryService" start=disabled

#Disable Visual Studio telemetry
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
Reg add "HKLM\Software\Policies\Microsoft\VisualStudio\SQM" /v OptIn /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
Reg add "HKCU\Software\Microsoft\VisualStudio\Telemetry" /v TurnOffSwitch /t REG_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v DisableFeedbackDialog /t REG_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v DisableEmailInput /t REG_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v DisableScreenshotCapture /t REG_DWORD /d 1 /f
sc stop "VSStandardCollectorService150"
Run net stop "VSStandardCollectorService150"
sc config "VSStandardCollectorService150" start=disabled

#Block Google Chrome Software Reporter Tool
Reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_SZ /d 0 /f
Reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_SZ /d 0 /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
Reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_SZ /d 0 /f

#Disable storing sensitive data in Acrobat Reader DC
Reg add "HKCU\Software\Adobe\Adobe ARM\1.0\ARM" /v "iCheck" /t REG_SZ /d 0 /f
Reg add "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "cSharePoint" /t REG_SZ /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" /v "bToggleAdobeDocumentServices" /t REG_SZ /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" /v "bToggleAdobeSign" /t REG_SZ /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" /v "bTogglePrefSync" /t REG_SZ /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" /v "bToggleWebConnectors" /t REG_SZ /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" /v "bAdobeSendPluginToggle" /t REG_SZ /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" /v "bUpdater" /t REG_SZ /d 0 /f

#Disable CCleaner Health Check
TaskKill /F ccleaner.exe
TaskKill /F ccleaner64.exe
Reg add "HKCU\Software\Piriform\CCleaner" /v "HomeScreen" /t REG_SZ /d 2 /f

#Disable CCleaner Monitoring && more
TASKKILL /F /FI "IMAGENAME eq CCleaner*"
schtasks /Change /TN "CCleaner Update" /Disable
Reg add "HKCU\Software\Piriform\CCleaner" /v "Monitoring" /t REG_SZ /d 0 /f
Reg add "HKCU\Software\Piriform\CCleaner" /v "HelpImproveCCleaner" /t REG_SZ /d 0 /f
Reg add "HKCU\Software\Piriform\CCleaner" /v "SystemMonitoring" /t REG_SZ /d 0 /f
Reg add "HKCU\Software\Piriform\CCleaner" /v "SystemMonitoringRunningNotification" /t REG_SZ /d 0 /f
Reg add "HKCU\Software\Piriform\CCleaner" /v "UpdateAuto" /t REG_SZ /d 0 /f
Reg add "HKCU\Software\Piriform\CCleaner" /v "UpdateCheck" /t REG_SZ /d 0 /f
Reg add "HKCU\Software\Piriform\CCleaner" /v "CheckTrialOffer" /t REG_SZ /d 0 /f
Reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)GetIpmForTrial" /t REG_SZ /d 0 /f
Reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdater" /t REG_SZ /d 0 /f
Reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdaterIpm" /t REG_SZ /d 0 /f

#Disable Dropbox Update service
sc config dbupdate start=disabled
sc config dbupdatem start=disabled
schtasks /Change /TN "DropboxUpdateTaskMachineCore" /disable
schtasks /Change /TN "DropboxUpdateTaskMachineUA" /disable

#Disable Google update service
schtasks /Change /TN "GoogleUpdateTaskMachineCore" /disable
schtasks /Change /TN "GoogleUpdateTaskMachineUA" /disable

#Disable Media Player telemetry
Reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f
Reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventCDDVDMetadataRetrieval" /t REG_DWORD /d 1 /f
Reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventMusicFileMetadataRetrieval" /t REG_DWORD /d 1 /f
Reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventRadioPresetsRetrieval" /t REG_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f
sc config WMPNetworkSvc start=disabled

#Disable Microsoft Office telemetry
Reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\osm" /v "Enablelogging" /t REG_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\osm" /v "EnableUpload" /t REG_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "Enablelogging" /t REG_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "EnableUpload" /t REG_DWORD /d 0 /f

#Disable Microsoft Windows Live ID service
Reg add "HKLM\SYSTEM\CurrentControlSet\services\wlidsvc" /v Start /t REG_DWORD /d 4 /f
sc config wlidsvc start=disabled

#Disable Mozilla Firefox telemetry
Reg add "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v "DisableDefaultBrowserAgent" /t REG_DWORD /d 1 /f

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










