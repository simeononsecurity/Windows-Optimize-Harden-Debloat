######SCRIPT FOR FULL INSTALL AND CONFIGURE ON STANDALONE MACHINE#####
#Microsoft Security Baselines
.\LGPO\LGPO.exe /g .\GPOs\Microsoft\"Windows 10 1909 Baseline"\GPOs
.\LGPO\LGPO.exe /g .\GPOs\Microsoft\"Microsoft Edge v80"\GPOs
.\LGPO\LGPO.exe /g .\GPOs\Microsoft\Office365-ProPlus-Sept2019-FINAL\GPOs
#Cyber.mil GPOs
.\LGPO\LGPO.exe /g .\GPOs\Cyber.mil
#SIMEONONSECURITY GPOS
.\LGPO\LGPO.exe /g .\GPOs\simeononsecurity

#Windows 10 Defenter Exploit Guard Configuration File
mkdir C:\temp\
mkdir "C:\temp\Windows Defender"
copy-item -Path .\Files\DOD_EP_V3.xml -Destination "C:\temp\Windows Defender" -Force -Recurse

#Copy  Policy Definitions for gpedit.msc
copy-item -Path .\PolicyDefinitions\* -Destination C:\Windows\PolicyDefinitions -Force -Recurse

#Package Management Scripts
#.\Scripts\"Package Management and Windows Updates"\installrsat.ps1
.\Scripts\"Package Management and Windows Updates"\chocoautomatewindowsupdates.ps1

#Security Scripts
.\Scripts\"Security, Hardening, and Mitigations"\"disable tcp timestamps.bat"
.\Scripts\"Security, Hardening, and Mitigations"\"IE Scripting Engine Memory Corruption.bat"
.\Scripts\"Security, Hardening, and Mitigations"\"specture meltdown mitigations.bat"

#Security Scripts Testing Required
#Only enable after testing in your environment
#.\Scripts\"Security, Hardening, and Mitigation"s\"SSL Hardening Registries.ps1"

#Debloating Scripts

#ONLY ENABLE IF ON VM
#.\Scripts\"Debloating, Optimization, and Privacy"\"Windows_10_VDI"\1909_WindowsUpdateEnabled\Win10_1909_VDI_Optimize.ps1

.\Scripts\"Debloating, Optimization, and Privacy"\ultimate performance mode.ps1
.\Scripts\"Debloating, Optimization, and Privacy"\startupcleantelem.ps1
.\Scripts\"Debloating, Optimization, and Privacy"\optimizevmvirtalization.ps1
.\Scripts\"Debloating, Optimization, and Privacy"\"Windows 10 Debloater"\Windows10SysPrepDebloater.ps1 -Sysprep -Debloat -Privacy
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to account info.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to calendar.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to call history.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to contacts.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to diagnostic information.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to documents.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to email.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to file system.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to location.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to messaging.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to motion.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to notifications.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to other devices.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to phone call.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to pictures.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to radios.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to tasks.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable app access to videos.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Apps\"Disable tracking of app starts.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Cortana\"Disable Bing in Windows Search.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Cortana\"Disable Cortana.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Edge\"Prevent Edge from running in background.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Edge\"Disable synchronization of data.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Edge\"Disable AutoFill for credit cards.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Gaming\"Disable Game Bar features.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Privacy\"Block automatic Installation of apps.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Privacy\"Disable Clipboard history.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Privacy\"Disable Compatibility Telemetry.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Privacy\"Disable Customer Experience Improvement Program.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Privacy\"Disable Location tracking.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Privacy\"Disable Telemetry.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Privacy\"Disable Timeline history.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Privacy\"Disable Wi-Fi Sense.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Privacy\"Disable Windows Tips.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Privacy\"Do not show feedback notifications.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Privacy\"Prevent using diagnostic data.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Privacy\"Turn off Advertising ID for Relevant Ads.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Privacy\"Turn off help Microsoft improve typing and writing.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Security\"Disable password reveal button.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Security\"Disable Windows Media DRM Internet Access.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Updates\"Disable forced Windows updates.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Updates\"Disable Windows updates sharing.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\scripts\Windows\"Disable Windows Error Reporting.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\debotnet\debotnetscripts.ps1
