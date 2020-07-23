**Optimizing and Hardening Windows 10 Deployments**

Download all the required files from the [GitHub Repository](https://github.com/smiltech/W10-Optimize-and-Harden)


Windows 10 is an invasive and insecure operating system out of the box. 
Organizations like [PrivacyTools.io](https://PrivacyTools.io), [Microsoft](https://microsoft.com) and the 
[Department of Defense](https://public.cyber.mil) have reccomended configuration changes to lockdown, harden, and secure the operating system. These changes cover a wide range of mitigations including blocking telemetery, macros, removing bloatware, and preventing many physical attacks on a system.



A list of script and tools this collection utilizes:

1.) [Microsoft Security Compliance Toolkit 1.0](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

2.) [Cyber.mil - Group Policy Objects](https://public.cyber.mil/stigs/gpo/)

3.) [Sycnex - Windows10Debloater](https://github.com/Sycnex/Windows10Debloater)

4.) [TheVDIGuys - Windows 10 VDI Optimize](https://github.com/TheVDIGuys/Windows_10_VDI_Optimize)

5.) [Mirinsoft - SharpApp](https://github.com/builtbybel/sharpapp)

6.) [Mirinsoft - debotnet] (https://github.com/builtbybel/debotnet)

Additional configurations were considered from:

[Disable TCP Timestamps](https://www.whonix.org/wiki/Disable_TCP_and_ICMP_Timestamps)

[IE Scripting Engine Memory Corruption](https://kb.cert.org/vuls/id/573168/)

[Specture and Meltdown Mitigations](https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities)

[SSL Hardening](https://dirteam.com/sander/2019/07/30/howto-disable-weak-protocols-cipher-suites-and-hashing-algorithms-on-web-application-proxies-ad-fs-servers-and-windows-servers-running-azure-ad-connect/)

[Windows 10 Privacy](https://docs.microsoft.com/en-us/windows/privacy/)

[Managing Windows 10 Telemetry and Callbacks](https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)

[Windows 10 VDI Reccomendations](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds_vdi-recommendations-1909)


The script we will be using must be launched from the directory containing all the other files from the [GitHub Repository](https://github.com/smiltech/W10-Optimize-and-Harden)

In order to enable the Windows 10 VDI Optimizations you must uncomment the line below:
```
.\Scripts\"Debloating, Optimization, and Privacy"\"Windows_10_VDI"\1909_WindowsUpdateEnabled\Win10_1909_VDI_Optimize.ps1

```
In order to enable the SSL Hardening you must uncomment the line below:
```
.\Scripts\"Security, Hardening, and Mitigation"s\"SSL Hardening Registries.ps1"

```

The script we will be using is called **"installallstandalone.ps1"** and its contents are:

```
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
```


**The script may be lauched from the extracted GitHub download like this:**
```
.\W10-Optimize-and-Harden-master\installallstandalone.ps1
```
