# Introduction 
Automatically apply settings referenced in white paper:

https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-1909 

These scripts are provided as a means to customize each VDI environment individually, in an easy to use manner.  The text files can be easily edited to prevent removing apps that are desired to be retained.

**NOTE:** As of 4/14/20, these scripts have been tested on **Windows Virtual Desktop (WVD)**.  A number of changes specific to the WVD full desktop experience have been incorporated into the latest version of these scripts.

# Getting Started
 ## DEPENDENCIES
 1. LGPO.EXE (available at https://www.microsoft.com/en-us/download/details.aspx?id=55319)
 2. Previously saved local group policy settings, available on the GitHub site where this script is located
 3. This PowerShell script

NOTE: This script can take 10 minutes or more to complete on the reference (gold) VM. A prompt to reboot will appear when the script has comoletely finished running. Wait for this prompt to confirm the script has successfully completed.

- REFERENCES:
https://social.technet.microsoft.com/wiki/contents/articles/7703.powershell-running-executables.aspx
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item?view=powershell-6
https://blogs.technet.microsoft.com/secguide/2016/01/21/lgpo-exe-local-group-policy-object-utility-v1-0/
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service?view=powershell-6
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item?view=powershell-6
https://msdn.microsoft.com/en-us/library/cc422938.aspx

- Appx package cleanup                 - Complete
- Scheduled tasks                      - Complete
- Automatic Windows traces             - Complete
- OneDrive cleanup                     - Complete
- Local group policy                   - Complete
- System services                      - Complete
- Disk cleanup                         - Complete
- Default User Profile Customization   - Complete

This script is dependant on three elements:
LGPO Settings folder, applied with the LGPO.exe Microsoft app

CHANGE HISTORY (Windows 10, 1909)
- Updated user profile settings to include setting background to blue, so not too much black
- Added a number of optimizations to shell settings for performance
- Updated services input file for service names instead of registry locations
- Disabling services using the Service Control Manager tool 'SC.EXE', not setting registry entries manually
- Changed the method of disabling services, with native PowerShell
- Fixed some small issues with input scripts that caused error messages
- Delete unused .EVTX and .ETL files (very small disk space savings)
- Added a reboot option prompt at the conclusion of the PowerShell script
- Added several LGPO settings to turn off privacy settings on new user logon
- Added settings in default user profile settings to disable suggested content in 'Settings'

# IMPORTANT ISSUE (01/17/2020)
IMPORTANT: There is a setting in the current LGPO files that should not be set by default. As of 1/17/10...
a fix has been checked in to the "Pending" branch.  Once we confirm that resolves the issue we will merge...
into the "Master" branch.  The issue is that Windows will not check certificate information, and thus...
program installations could fail.  The temporary workaround is to open GPEDIT.MSC on the reference image...
The set the policy to "not configured".  Here is the location of the policy setting:

**Local Computer Policy \ Computer Configuration \ Administrative Templates \ System \ Internet Communication Management \ Internet Communication settings**

```
Turn off Automatic Root Certificates Update
```
# IMPORTANT ISSUE (04/14/2020)
IMPORTANT: A local GPO setting previously included, could prevent the activation of Office 365 in Windows Virtual Desktop.
The issue is with Windows Network Connectivity Status Indicator tests.  Disabling these tests also changes the network icon...
on the taskbar from Connected to "status unknown".  This setting was changed back to "not configured as of 4/14/2020.

**Local Computer Policy \ Computer Configuration \ Administrative Templates \ System \ Internet Communication Management \ Internet Communication settings**

```
Turn off Windows Network Connectivity Status Indicator active tests
```
# MINOR ISSUE (04/29/2020)
Background app resource usage issue.  If you choose to keep several of the UWP apps, such as Photos, Skype, and Phone, you may notice that these apps will start up and run in the background, even though a user has not started the app.  This behavior can be controlled through the 'Settings' app, under 'Background apps'.  If you toggle these apps' setting to "off", now the app will not automatically start and run in the background when users logon.  The background resource usage is low, but can add up in multi-session environments.

The issue is that there is not currently a policy that provides a global toggle for these apps.  There are a few ways this can be addressed in the short-term.

1. Set a Group Policy Preference to automatically set the following registry values

`"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe /v Disabled /t REG_DWORD /d 1`
`"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe /v DisabledByUser /t REG_DWORD /d 1`
`"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c /v Disabled /t REG_DWORD /d 1`
`"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c /v DisabledByUser /t REG_DWORD /d 1`
`"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe /v Disabled /t REG_DWORD /d 1`
`"HKCU\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe /v DisabledByUser /t REG_DWORD /d 1`

2. Uninstall the apps for "AllUsers", and optionally delete the payload.  The text input file "Win10_1909_AppxPackages.txt" uninstalls these apps by default.

3. Edit the default user registry hive, which these scripts do.  The REG.EXE commands have been recently added to the file "Win10_1909_DefaultUserSettings.txt" in this repository.  That way if you want to keep one or all of these apps, and still control the behavior, you can do so with the scripting method.

Please note that the registry settings listed here are subject to change.

