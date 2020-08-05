# Optimizing and Hardening Windows 10 Deployments

**Download all the required files from the [GitHub Repository](https://github.com/smiltech/W10-Optimize-and-Harden)**

Windows 10 is an invasive and insecure operating system out of the box. 
Organizations like [PrivacyTools.io](https://PrivacyTools.io), [Microsoft](https://microsoft.com), [Cyber.mil](https://public.cyber.mil), the [Department of Defense](https://dod.gov), and the [National Security Agency](https://www.nsa.gov/) have recommended configuration changes to lockdown, harden, and secure the operating system. These changes cover a wide range of mitigations including blocking telemetry, macros, removing bloatware, and preventing many physical attacks on a system.

## Requirements:
- [X] Windows 10 Professional or Windows 10 Enterprise (**Preferred**)
  - Windows 10 Home does not allow for GPO configurations. 
  - Windows 10 "N" Editions are not tested.
- [x] [Standards](https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure) for a highly secure Windows 10 device
- [x] System is [fully up to date](https://support.microsoft.com/en-gb/help/4027667/windows-10-update)
  - Currently Windows 10 **v1909** or **v2004**. Run the [Windows 10 Upgrade Assistant](https://support.microsoft.com/en-us/help/3159635/windows-10-update-assistant) to be update and verify latest major release.
- [X] Hardware Requirements
  - [Hardware Requirements for Memory Integrity](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/requirements-and-deployment-planning-guidelines-for-virtualization-based-protection-of-code-integrity#baseline-protections) 
  - [Hardware Requirements for Windows Defender Application Guard](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard)
  - [Hardware Requirements for Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements)
  
## Recommended reading material:
  - [System Guard Secure Launch](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection#requirements-met-by-system-guard-enabled-machines)
  - [System Guard Root of Trust](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-how-hardware-based-root-of-trust-helps-protect-windows)
  - [Hardware-based Isolation](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/overview-hardware-based-isolation)
  - [Memory integrity](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/memory-integrity)
  - [Windows Defender Application Guard](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/wd-app-guard-overview)
  - [Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works)

## A list of scripts and tools this collection utilizes:

- [Microsoft Security Compliance Toolkit 1.0](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

- [Cyber.mil - Group Policy Objects](https://public.cyber.mil/stigs/gpo/)

- [Sycnex - Windows10Debloater](https://github.com/Sycnex/Windows10Debloater)

- [TheVDIGuys - Windows 10 VDI Optimize](https://github.com/TheVDIGuys/Windows_10_VDI_Optimize)

- [Mirinsoft - SharpApp](https://github.com/builtbybel/sharpapp)

- [Mirinsoft - debotnet](https://github.com/builtbybel/debotnet)

- [NSACyber - Bitlocker Guidance](https://github.com/nsacyber/BitLocker-Guidance)

- [0x6d69636b - Windows Hardening](https://github.com/0x6d69636b/windows_hardening)

- [SysInternals - AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)

- [W4H4WK - Debloat Windows 10](https://github.com/W4RH4WK/Debloat-Windows-10/tree/master/scripts)

## Additional configurations were considered from:

- [NSACyber - Hardware-and-Firmware-Security-Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance)

- [NSACyber - Application Whitelisting Using Microsoft AppLocker](https://apps.nsa.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm)

- [Whonix - Disable TCP Timestamps](https://www.whonix.org/wiki/Disable_TCP_and_ICMP_Timestamps)

- [CERT - IE Scripting Engine Memory Corruption](https://kb.cert.org/vuls/id/573168/)

- [Dirteam - SSL Hardening](https://dirteam.com/sander/2019/07/30/howto-disable-weak-protocols-cipher-suites-and-hashing-algorithms-on-web-application-proxies-ad-fs-servers-and-windows-servers-running-azure-ad-connect/)

- [Microsoft - Specture and Meltdown Mitigations](https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities)

- [Microsoft - Windows 10 Privacy](https://docs.microsoft.com/en-us/windows/privacy/)

- [Microsoft - Managing Windows 10 Telemetry and Callbacks](https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)

- [Microsoft - Windows 10 VDI Recomendations](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds_vdi-recommendations-1909)


## STIGS/SRGs Applied:
 
- [Windows 10 V1R23](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_10_V1R23_STIG.zip)

- [Windows Defender Antivirus V1R9](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Defender_Antivirus_V1R9_STIG.zip)

- [Windows Firewall V1R7](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Windows_Firewall_V1R7_STIG.zip)

- [Internet Explorer 11 V1R19](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_IE11_V1R19_STIG.zip)

- [Google Chrome V1R19](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Google_Chrome_V1R19_STIG.zip)

- [Firefox V4R29*](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MOZ_FireFox_V4R29_STIG.zip) - **WIP**

- [Adobe Reader Pro DC Continous V1R2](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Adobe_Acrobat_Pro_DC_Continuous_V1R2_STIG.zip)

- [Microsoft Office 2019/Office 365 Pro Plus V1R2](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Office_365_ProPlus_V1R2_STIG.zip)

- [Microsoft Office 2016 V1R2](https://dl.dod.cyber.mil/wp-content/uploads/stigs/pdf/U_Microsoft_Office_2016_V1R2_Overview.pdf)

- [Microsoft Office 2013 V1R5](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MicrosoftOffice2013_V1R5_Overview.zip)


## How to run the script

**The script may be lauched from the extracted GitHub download like this:**
```
.\W10-Optimize-and-Harden-master\installallstandalone.ps1
```
The script we will be using must be launched from the directory containing all the other files from the [GitHub Repository](https://github.com/smiltech/W10-Optimize-and-Harden)


**In order to enable the Windows 10 VDI Optimizations you must uncomment the line below:**
```
.\Files\Scripts\"Debloating, Optimization, and Privacy"\"Windows_10_VDI"\1909_WindowsUpdateEnabled\Win10_1909_VDI_Optimize.ps1

```

**In order to enable the SSL Hardening you must uncomment the line below:**
```
.\Files\Scripts\Package Management and Windows Updates\sos-installpsmodules.ps1

```

**The script we will be using is called **"installallstandalone.ps1"** and its contents are:**

```
######SCRIPT FOR FULL INSTALL AND CONFIGURE ON STANDALONE MACHINE#####
#Continue on error
$ErrorActionPreference= 'silentlycontinue'

#Require elivation for script run
Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

#Unblock all files required for script
ls *.ps*1 -recurse | Unblock-File

#Windows 10 Defenter Exploit Guard Configuration File
start-job -ScriptBlock {mkdir C:\temp\; mkdir "C:\temp\Windows Defender"; copy-item -Path .\Files\DOD_EP_V3.xml -Destination "C:\temp\Windows Defender" -Force -Recurse -ErrorAction SilentlyContinue} 

#Install Required PSModules
.\Files\Scripts\"Package Management and Windows Updates"\sos-installpsmodules.ps1

##Install Latest Windows Updates
start-script -ScriptBlock {Install-WindowsUpdate -MicrosoftUpdate -AcceptAll; Get-WuInstall -AcceptAll -IgnoreReboot; Get-WuInstall -AcceptAll -Install -IgnoreReboot}

#Optional Scripts 
#.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-ssl-hardening.ps1
#.\Files\Scripts\"Debloating, Optimization, and Privacy"\"Windows_10_VDI"\1909_WindowsUpdateEnabled\Win10_1909_VDI_Optimize.ps1

#Security Scripts
.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-installadmxtemplates.ps1
.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-disable-tcp-timestamps.bat
.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-IE-Scripting-Engine-Memory-Corruption.bat
.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-specture-meltdown-mitigations.bat
.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-FireFoxConfInstall.ps1
.\Files\Scripts\"Security, Hardening, and Mitigations"\HardeningKitty\sos-kitty.ps1

#Debloating Scripts
.\Files\Scripts\"Debloating, Optimization, and Privacy"\"Windows 10 Debloater"\Windows10SysPrepDebloater.ps1 -Sysprep -Debloat -Privacy
.\Files\Scripts\"Debloating, Optimization, and Privacy"\sos-ultimate-performance-mode.ps1
.\Files\Scripts\"Debloating, Optimization, and Privacy"\sos-optimizevmvirtalization.ps1
.\Files\Scripts\"Debloating, Optimization, and Privacy"\sos-startupcleantelem.ps1
.\Files\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\sos-sharpappscripts.ps1
.\Files\Scripts\"Debloating, Optimization, and Privacy"\debotnet\sos-debotnetscripts.ps1
.\Files\Scripts\"Debloating, Optimization, and Privacy"\W4H4Wk\sos-w4h4wk.ps1

#GPO Configurations
#Microsoft Security Baselines
.\Files\LGPO\LGPO.exe /g .\Files\GPOs\Microsoft\"Windows 10 1909 Baseline"\GPOs
.\Files\LGPO\LGPO.exe /g .\Files\GPOs\Microsoft\"Microsoft Edge v80"\GPOs
.\Files\LGPO\LGPO.exe /g .\Files\GPOs\Microsoft\Office365-ProPlus-Sept2019-FINAL\GPOs
#Cyber.mil GPOs
.\Files\LGPO\LGPO.exe /g .\Files\GPOs\Cyber.mil
#NSACyber GPOs
.\Files\LGPO\LGPO.exe /g .\Files\GPOs\NSACyber\Computer
#SIMEONONSECURITY GPOS
.\Files\LGPO\LGPO.exe /g .\Files\GPOs\simeononsecurity
```

