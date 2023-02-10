# Optimize, Harden, and Debloat Windows 10 and Windows 11 Deployments
[![Script Test CICD](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat/actions/workflows/test-with-docker.yml/badge.svg)](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat/actions/workflows/test-with-docker.yml)[![VirusTotal Scan](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat/actions/workflows/virustotal.yml/badge.svg)](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat/actions/workflows/virustotal.yml)[![PSScriptAnalyzer](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat/actions/workflows/powershell.yml/badge.svg)](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat/actions/workflows/powershell.yml) 

## Introduction:

Windows 10 and Windows 11 are invasive and insecure operating system out of the box.
Organizations like [PrivacyTools.io](https://PrivacyTools.io), [Microsoft](https://microsoft.com), [Cyber.mil](https://public.cyber.mil), the [Department of Defense](https://dod.gov), and the [National Security Agency](https://www.nsa.gov/) have recommended configuration changes to lockdown, harden, and secure the operating system. These changes cover a wide range of mitigations including blocking telemetry, macros, removing bloatware, and preventing many digital and physical attacks on a system. This script aims to automate the configurations recommended by those organizations.

## Notes, Warnings, and Considerations:

**WARNING:**

This script should work for most, if not all, systems without issue. While [@SimeonOnSecurity](https://github.com/simeononsecurity) creates, reviews, and tests each repo intensively, we can not test every possible configuration nor does [@SimeonOnSecurity](https://github.com/simeononsecurity) take any responsibility for breaking your system. If something goes wrong, be prepared to submit an [issue](../../issues).

- This script is designed for operation in primarily **Personal Use** environments. With that in mind, certain enterprise configuration settings are not implemented. This script is not designed to bring a system to 100% compliance. Rather it should be used as a stepping stone to complete most, if not all, the configuration changes that can be scripted while skipping past issues like branding and banners where those should not be implemented even in a hardened personal use environment.
- This script is designed in such a way that the optimizations, unlike some other scripts, will not break core windows functionality.
- Features like Windows Update, Windows Defender, the Windows Store, and Cortona have been restricted, but are not in a dysfunctional state like most other Windows 10 Privacy scripts.
- If you seek a minimized script targeted only to commercial environments, please see this [GitHub Repository](https://github.com/simeononsecurity/Standalone-Windows-STIG-Script)


**Do not run this script if you don't understand what it does. It is your responsibility to review and test the script before running it.**

**FOR EXAMPLE, THE FOLLOWING WILL BREAK IF YOU RUN THIS WITHOUT TAKING PREVENTATIVE STEPS:**

- Using the default administrator account named "Administrator" is disabled and renamed per DoD STIG

  - Does not apply to the default account created but does apply to using the Default Administrator account often found on Enterprise, IOT, and Windows Server Versions

  - Create a new account under Computer Management and set it as an administrator if you wish. Then copy the contents of the previous users folder into the new one after signing into the new user for the first time to work around this prior to running the script.

- Signing in using a microsoft account is disabled per DoD STIG. 

  - When trying to be secure and private, signing into your local account via a Microsoft Account is not advised. This is enforced by this repo.

  - Create a new account under Computer Management and set it as an administrator if you wish. Then copy the contents of the previous users folder into the new one after signing into the new user for the first time to work around this prior to running the script.

- Account PINs are disabled per DoD STIG

  - PINs are insecure when used solely in place of a password and can be easily bypassed in a matter of hours or potentially even seconds or minutes

  - Remove the pin from the account and/or sign in using password after running the script.

- Bitlocker defaults are changed and hardened due to DoD STIG.

  - Due to how bitlocker is implemented, when this changes occur and if you already have bitlocker enabled it will break the bitlocker implementation. 

  - Disable bitlocker, run the script, then reenable bitlocker to workaround this issue. 

## Requirements:

- [x] Windows 10/11 Enterprise (**Preferred**) or Professional
  - Windows 10/11 Home editions do not support GPO configurations and are not tested.
  - Window "N" Editions are not tested.
- [x] [Standards](https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure) for a highly secure Windows 10 device
- [x] System is [fully up to date and supported](https://support.microsoft.com/en-gb/help/4027667/windows-10-update)
  - Run the [Windows Upgrade Assistant](https://support.microsoft.com/en-us/help/3159635/windows-10-update-assistant) to update and verify latest major release.
- [x] Bitlocker must be suspended or turned off prior to implementing this script, it can be enabled again after rebooting.
  - Follow-up runs of this script can be run without disabling bitlocker.
- [x] Hardware Requirements
  - [Hardware Requirements for Memory Integrity](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/requirements-and-deployment-planning-guidelines-for-virtualization-based-protection-of-code-integrity#baseline-protections)
  - [Hardware Requirements for Virtualization-Based Security](https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs)
  - [Hardware Requirements for Windows Defender Application Guard](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard)
  - [Hardware Requirements for Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements)

## Recommended reading material:

- [System Guard Secure Launch](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection#requirements-met-by-system-guard-enabled-machines)
- [System Guard Root of Trust](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-how-hardware-based-root-of-trust-helps-protect-windows)
- [Hardware-based Isolation](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/overview-hardware-based-isolation)
- [Memory integrity](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/memory-integrity)
- [Windows Defender Application Guard](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/wd-app-guard-overview)
- [Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works)

## Additions, notable changes, and bugfixes:

**This script adds, removes, and changes settings on your system. Please review the script before running it.**

### Browsers:

- Browsers will have additional extentions installed to aid in privacy and security.
  - See [here](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat/issues/11) for additional information.
- Due to the DoD STIGs implemented for browsers, extension management and other enterprise settings are set. For instructions on how to see these options, you'll need to look at the GPO instructions below.

### Powershell Modules:

- To aid in automating Windows Updates the PowerShell [PSWindowsUpdate](https://www.powershellgallery.com/packages/PSWindowsUpdate/2.0.0.4) module will be added to your system.

### Fixing Microsoft Account, Store, or Xbox Services:

This is because we block signing into microsoft accounts. Microsoft's telemetry and identity association is frowned upon.
However, if you still wish to use these services see the following issue tickets for the resolution:

- https://github.com/simeononsecurity/Windows-Optimize-Debloat/issues/1
- https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat/issues/16
- https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat/issues/22

### Editing policies in Local Group Policy after the fact:

If you need to modify or change a setting, they are most likely configurable via GPO:

- Import the ADMX Policy definitions from this [repo](https://github.com/simeononsecurity/STIG-Compliant-Domain-Prep/tree/master/Files/PolicyDefinitions) into _C:\windows\PolicyDefinitions_ on the system you're trying to modify.

- Open `gpedit.msc` on on the system you're trying to modify.

## A list of scripts and tools this collection utilizes:

### First Party:

- [.NET-STIG-Script](https://github.com/simeononsecurity/.NET-STIG-Script)
- [Automate-Sysmon](https://github.com/simeononsecurity/Automate-Sysmon)
- [FireFox-STIG-Script](https://github.com/simeononsecurity/FireFox-STIG-Script)
- [JAVA-STIG-Script](https://github.com/simeononsecurity/JAVA-STIG-Script)
- [Standalone-Windows-STIG-Script](https://github.com/simeononsecurity/Standalone-Windows-STIG-Script)
- [Windows-Defender-STIG-Script](https://github.com/simeononsecurity/Windows-Defender-STIG-Script)
- [Windows-Optimize-Debloat](https://github.com/simeononsecurity/Windows-Optimize-Debloat)

### Third Party:

- [Cyber.mil - Group Policy Objects](https://public.cyber.mil/stigs/gpo/)
- [Microsoft Security Compliance Toolkit 1.0](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
- [Microsoft Sysinternals - Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

## STIGS/SRGs Applied:

- [Adobe Acrobat Pro DC Continuous V2R1](https://public.cyber.mil/stigs/downloads/)
- [Adobe Acrobat Reader DC Continuous V2R1](https://public.cyber.mil/stigs/downloads/)
- [Firefox V5R2](https://public.cyber.mil/stigs/downloads/)
- [Google Chrome V2R4](https://public.cyber.mil/stigs/downloads/)
- [Internet Explorer 11 V1R19](https://public.cyber.mil/stigs/downloads/)
- [Microsoft Edge V1R2](https://public.cyber.mil/stigs/downloads/)
- [Microsoft .Net Framework 4 V1R9](https://public.cyber.mil/stigs/downloads/)
- [Microsoft Office 2013 V2R1](https://public.cyber.mil/stigs/downloads/)
- [Microsoft Office 2016 V2R1](https://public.cyber.mil/stigs/downloads/)
- [Microsoft Office 2019/Office 365 Pro Plus V2R3](https://public.cyber.mil/stigs/downloads/)
- [Microsoft OneDrive STIG V2R1](https://public.cyber.mil/stigs/downloads/)
- [Oracle JRE 8 V1R5](https://public.cyber.mil/stigs/downloads/)
- [Windows 10 V2R2](https://public.cyber.mil/stigs/downloads/)
- [Windows Defender Antivirus V2R2](https://public.cyber.mil/stigs/downloads/)
- [Windows Firewall V1R7](https://public.cyber.mil/stigs/downloads/)

## Additional configurations were considered from:

- [BuiltByBel - PrivateZilla](https://github.com/builtbybel/privatezilla)
- [CERT - IE Scripting Engine Memory Corruption](https://kb.cert.org/vuls/id/573168/)
- [Dirteam - SSL Hardening](https://dirteam.com/sander/2019/07/30/howto-disable-weak-protocols-cipher-suites-and-hashing-algorithms-on-web-application-proxies-ad-fs-servers-and-windows-servers-running-azure-ad-connect/)
- [MelodysTweaks - Basic Tweaks](https://sites.google.com/view/melodystweaks/basictweaks)
- [Microsoft - Managing Windows 10 Telemetry and Callbacks](https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)
- [Microsoft - Reduce attack surfaces with attack surface reduction rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction)
- [Microsoft - Recommended block rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)
- [Microsoft - Recommended driver block rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)
- [Microsoft - Specture and Meltdown Mitigations](https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities)
- [Microsoft - Windows 10 Privacy](https://docs.microsoft.com/en-us/windows/privacy/)
- [Microsoft - Windows 10 VDI Recomendations](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds_vdi-recommendations-1909)
- [Microsoft - Windows Defender Application Control](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control-design-guide)
- [Mirinsoft - SharpApp](https://github.com/builtbybel/sharpapp)
- [Mirinsoft - debotnet](https://github.com/builtbybel/debotnet)
- [NSACyber - Application Whitelisting Using Microsoft AppLocker](https://apps.nsa.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm)
- [NSACyber - Bitlocker Guidance](https://github.com/nsacyber/BitLocker-Guidance)
- [NSACyber - Hardware-and-Firmware-Security-Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance)
- [NSACyber - Windows Secure Host Baseline](https://github.com/nsacyber/Windows-Secure-Host-Baseline)
- [UnderGroundWires - Privacy.S\*\*Y](https://github.com/undergroundwires/privacy.sexy)
- [Sycnex - Windows10Debloater](https://github.com/Sycnex/Windows10Debloater)
- [The-Virtual-Desktop-Team - Virtual-Desktop-Optimization-Tool](https://github.com/The-Virtual-Desktop-Team/Virtual-Desktop-Optimization-Tool)
- [TheVDIGuys - Windows 10 VDI Optimize](https://github.com/TheVDIGuys/Windows_10_VDI_Optimize)
- [VectorBCO - windows-path-enumerate](https://github.com/VectorBCO/windows-path-enumerate)
- [W4H4WK - Debloat Windows 10](https://github.com/W4RH4WK/Debloat-Windows-10/tree/master/scripts)
- [Whonix - Disable TCP Timestamps](https://www.whonix.org/wiki/Disable_TCP_and_ICMP_Timestamps)

## How to run the script:
### GUI - Guided Install:

Download the latest release [here](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat-GUI/releases/), choose the options you want and hit execute.

<img src="https://raw.githubusercontent.com/simeononsecurity/Windows-Optimize-Harden-Debloat/master/.github/images/WOHD-GUI.gif" alt="Example of 
Windows-Optimize-Harden-Debloat GUI Based Guided install">

### Automated Install:

Use this one-liner to automatically download, unzip all supporting files, and run the latest version of the script.

```powershell
iwr -useb 'https://simeononsecurity.ch/scripts/windowsoptimizeandharden.ps1'|iex
```

<img src="https://raw.githubusercontent.com/simeononsecurity/Windows-Optimize-Harden-Debloat/master/.github/images/w10automatic.gif" alt="Example of 
Windows-Optimize-Harden-Debloat automatic install">

### Manual Install:

If manually downloaded, the script must be launched from an administrative powershell in the directory containing all the files from the [GitHub Repository](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat)

The script "sos-optimize-windows.ps1" includes several parameters that allow for customization of the optimization process. Each parameter is a boolean value that defaults to true if not specified.

- **cleargpos**: Clears Group Policy Objects settings.
- **installupdates**: Installs updates to the system.
- **adobe**: Implements the Adobe Acrobat Reader STIGs.
- **firefox**: Implements the FireFox STIG.
- **chrome**: Implements the Google Chrome STIG.
- **IE11**: Implements the Internet Explorer 11 STIG.
- **edge**: Implements the Microsoft Chromium Edge STIG.
- **dotnet**: Implements the Dot Net 4 STIG.
- **office**: Implements the Microsoft Office Related STIGs.
- **onedrive**: Implements the Onedrive STIGs.
- **java**: Implements the Oracle Java JRE 8 STIG.
- **windows**: Implements the Windows Desktop STIGs.
- **defender**: Implements the Windows Defender STIG.
- **firewall**: Implements the Windows Firewall STIG.
- **mitigations**: Implements General Best Practice Mitigations.
- **defenderhardening**: Implements and Hardens Windows Defender Beyond STIG Requirements.
- **pshardening**: Implements PowerShell Hardening and Logging.
- **sslhardening**: Implements SSL Hardening.
- **smbhardening**: Hardens SMB Client and Server Settings.
- **applockerhardening**: Installs and Configures Applocker (In Audit Only Mode).
- **bitlockerhardening**: Harden Bitlocker Implementation.
- **removebloatware**: Removes unnecessary programs and features from the system.
- **disabletelemetry**: Disables data collection and telemetry.
- **privacy**: Makes changes to improve privacy.
- **imagecleanup**: Cleans up unneeded files from the system.
- **nessusPID**: Resolves Unquoted System Strings in Path.
- **sysmon**: Installs and configures sysmon to improve auditing capabilities.
- **diskcompression**: Compresses the system disk.
- **emet**: Implements STIG Requirements and Hardening for EMET on Windows 7 Systems.
- **updatemanagement**: Changes the way updates are managed and improved on the system.
- **deviceguard**: Enables Device Guard Hardening.
- **sosbrowsers**: Optimizes the system's web browsers.

An example of how to launch the script with specific parameters would be:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
Get-ChildItem -Recurse *.ps1 | Unblock-File
powershell.exe -ExecutionPolicy ByPass -File .\sos-optimize-windows.ps1 -cleargpos:$false -installupdates:$false
```
