# Optimizing and Hardening Windows 10 Deployments

**Download all the required files from the [GitHub Repository](https://github.com/smiltech/W10-Optimize-and-Harden)**


Windows 10 is an invasive and insecure operating system out of the box. 
Organizations like [PrivacyTools.io](https://PrivacyTools.io), [Microsoft](https://microsoft.com), [Cyber.mil](https://public.cyber.mil), the [Department of Defense](https://dod.gov), and the [National Security Agency](https://www.nsa.gov/) have recomended configuration changes to lockdown, harden, and secure the operating system. These changes cover a wide range of mitigations including blocking telemetery, macros, removing bloatware, and preventing many physical attacks on a system.

## Requirements:
- [X] Windows 10 Professional or Windows 10 Enterprise (**Prefered**)
- [X] - Windows 10 Home does not allow for GPO configurations. Windows 10 "N" Editions are not tested.
- [x] [Standards](https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure) for a highly secure Windows 10 device
- [x] Latest [Windows 10 stable version](https://www.microsoft.com/en-us/software-download/windows10)
- [x] System is [fully up to date](https://support.microsoft.com/en-gb/help/4027667/windows-10-update)
- [x] (default activated) internal Windows Defender protection instead of external "Security" solutions
- [x] [Hardware Requirements](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection#requirements-met-by-system-guard-enabled-machines) for [System Guard](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-how-hardware-based-root-of-trust-helps-protect-windows) / [Hardware-based Isolation](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/overview-hardware-based-isolation)
- [x] [Hardware Requirements](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/requirements-and-deployment-planning-guidelines-for-virtualization-based-protection-of-code-integrity#baseline-protections) for [Memory integrity](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/memory-integrity)
- [x] [Hardware Requirements](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard) for Windows [Defender Application Guard](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/wd-app-guard-overview) (WDAG)
- [x] [Hardware Requirements](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements) for Windows [Defender Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works)


## A list of scripts and tools this collection utilizes:

1.) [Microsoft Security Compliance Toolkit 1.0](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

2.) [Cyber.mil - Group Policy Objects](https://public.cyber.mil/stigs/gpo/)

3.) [Sycnex - Windows10Debloater](https://github.com/Sycnex/Windows10Debloater)

4.) [TheVDIGuys - Windows 10 VDI Optimize](https://github.com/TheVDIGuys/Windows_10_VDI_Optimize)

5.) [Mirinsoft - SharpApp](https://github.com/builtbybel/sharpapp)

6.) [Mirinsoft - debotnet](https://github.com/builtbybel/debotnet)

7.) [NSACyber - Bitlocker Guidance](https://github.com/nsacyber/BitLocker-Guidance)

8.) [0x6d69636b - Windows Hardening](https://github.com/0x6d69636b/windows_hardening)

## Additional configurations were considered from:

[NSACyber - Hardware-and-Firmware-Security-Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance)

[NSACyber - Application Whitelisting Using Microsoft AppLocker](https://apps.nsa.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm)

[Whonix - Disable TCP Timestamps](https://www.whonix.org/wiki/Disable_TCP_and_ICMP_Timestamps)

[CERT - IE Scripting Engine Memory Corruption](https://kb.cert.org/vuls/id/573168/)

[Dirteam - SSL Hardening](https://dirteam.com/sander/2019/07/30/howto-disable-weak-protocols-cipher-suites-and-hashing-algorithms-on-web-application-proxies-ad-fs-servers-and-windows-servers-running-azure-ad-connect/)

[Microsoft - Specture and Meltdown Mitigations](https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities)

[Microsoft - Windows 10 Privacy](https://docs.microsoft.com/en-us/windows/privacy/)

[Microsoft - Managing Windows 10 Telemetry and Callbacks](https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)

[Microsoft - Windows 10 VDI Recomendations](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds_vdi-recommendations-1909)


## How to run the script

**The script may be lauched from the extracted GitHub download like this:**
```
.\W10-Optimize-and-Harden-master\installallstandalone.ps1
```
**Or with the optional executable**

```
.\W10-Optimize-and-Harden-master\installallstandalone.exe
```
The script we will be using must be launched from the directory containing all the other files from the [GitHub Repository](https://github.com/smiltech/W10-Optimize-and-Harden)

**In order to enable the Windows 10 VDI Optimizations you must uncomment the line below:**
```
.\Scripts\"Debloating, Optimization, and Privacy"\"Windows_10_VDI"\1909_WindowsUpdateEnabled\Win10_1909_VDI_Optimize.ps1

```

**In order to enable the SSL Hardening you must uncomment the line below:**
```
.\Scripts\"Security, Hardening, and Mitigation"\"SSL Hardening Registries.ps1"

```

**The script we will be using is called **"installallstandalone.ps1"** and its contents are:**

```
######SCRIPT FOR FULL INSTALL AND CONFIGURE ON STANDALONE MACHINE#####

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
.\Scripts\"Security, Hardening, and Mitigations"\HardeningKitty\soskitty.ps1

#Security Scripts Testing Required
#Only enable after testing in your environment
#.\Scripts\"Security, Hardening, and Mitigations"\"SSL Hardening Registries.ps1"

#Debloating Scripts

#ONLY ENABLE IF ON VM
#.\Scripts\"Debloating, Optimization, and Privacy"\"Windows_10_VDI"\1909_WindowsUpdateEnabled\Win10_1909_VDI_Optimize.ps1

.\Scripts\"Debloating, Optimization, and Privacy"\"Windows 10 Debloater"\Windows10SysPrepDebloater.ps1 -Sysprep -Debloat -Privacy
.\Scripts\"Debloating, Optimization, and Privacy"\"ultimate performance mode.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\optimizevmvirtalization.ps1
.\Scripts\"Debloating, Optimization, and Privacy"\startupcleantelem.ps1
.\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\sharpappscripts.ps1
.\Scripts\"Debloating, Optimization, and Privacy"\debotnet\debotnetscripts.ps1

#GPO Configurations
#Microsoft Security Baselines
.\LGPO\LGPO.exe /g .\GPOs\Microsoft\"Windows 10 1909 Baseline"\GPOs
.\LGPO\LGPO.exe /g .\GPOs\Microsoft\"Microsoft Edge v80"\GPOs
.\LGPO\LGPO.exe /g .\GPOs\Microsoft\Office365-ProPlus-Sept2019-FINAL\GPOs
#Cyber.mil GPOs
.\LGPO\LGPO.exe /g .\GPOs\Cyber.mil
#NSACyber GPOs
.\LGPO\LGPO.exe /g .\GPOs\NSACyber\Computer
#SIMEONONSECURITY GPOS
.\LGPO\LGPO.exe /g .\GPOs\simeononsecurity
```

