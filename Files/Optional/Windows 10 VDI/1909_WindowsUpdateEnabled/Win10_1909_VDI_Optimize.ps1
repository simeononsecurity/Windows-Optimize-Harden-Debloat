#Requires -RunAsAdministrator
<#
- TITLE:          Microsoft Windows 1909  VDI/WVD Optimization Script
- AUTHORED BY:    Robert M. Smith and Tim Muessig (Microsoft Premier Services)
- AUTHORED DATE:  11/19/2019
- LAST UPDATED:   04/10/2020
- PURPOSE:        To automatically apply setting referenced in white paper:
                  "Optimizing Windows 10, Build 1909, for a Virtual Desktop Infrastructure (VDI) role"
                  URL: TBD

- Important:      Every setting in this script and input files are possible recommendations only,
                  and NOT requirements in any way. Please evaluate every setting for applicability
                  to your specific environment. These scripts have been tested on plain Hyper-V
                  VMs. Please test thoroughly in your environment before implementation

- DEPENDENCIES    1. LGPO.EXE (available at https://www.microsoft.com/en-us/download/details.aspx?id=55319)
                  2. LGPO database files available on the GitHub site where this script is located
                  3. This PowerShell script
                  4. The text input files containing all the apps, services, traces, etc. that you...
                     may be interested in disabling. Please review these input files to customize...
                     to your environment/requirements

- REFERENCES:
https://social.technet.microsoft.com/wiki/contents/articles/7703.powershell-running-executables.aspx
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item?view=powershell-6
https://blogs.technet.microsoft.com/secguide/2016/01/21/lgpo-exe-local-group-policy-object-utility-v1-0/
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service?view=powershell-6
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item?view=powershell-6
https://msdn.microsoft.com/en-us/library/cc422938.aspx

<# Categories of cleanup items:
- Appx package cleanup                 - Complete
- Scheduled tasks                      - Complete
- Automatic Windows traces             - Complete
- Local group policy                   - Complete
- System services                      - Complete
- Disk cleanup                         - Complete
- Default User Profile Customization   - Complete

This script is dependent on three elements:
LGPO Settings folder, applied with the LGPO.exe Microsoft app

The UWP app input file contains the list of almost all the UWP application packages that can be removed with PowerShell interactively.  
The Store and a few others, such as Wallet, were left off intentionally.  Though it is possible to remove the Store app, 
it is nearly impossible to get it back.  Please review the lists below and comment out or remove references to packages that you do not want to remove.
#>

Set-Location $PSScriptRoot
#region Disable, then remove, Windows Media Player including payload
    
Try
{
    Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer 
    Get-WindowsPackage -Online -PackageName "*Windows-mediaplayer*" | ForEach-Object { Remove-WindowsPackage -PackageName $_.PackageName -Online -ErrorAction SilentlyContinue }
}
Catch { }

#endregion

#region Begin Clean APPX Packages
Set-Location $PSScriptRoot

If (Test-Path .\Win10_1909_AppxPackages.txt)
{
    $AppxPackage = Get-Content .\Win10_1909_AppxPackages.txt
}

If ($AppxPackage.Count -gt 0)
{
    Foreach ($Item in $AppxPackage)
    {
        $Package = "*$Item*"
        Get-AppxPackage                    | Where-Object {$_.PackageFullName -like $Package} | Remove-AppxPackage
        Get-AppxPackage -AllUsers          | Where-Object {$_.PackageFullName -like $Package} | Remove-AppxPackage -AllUsers
        Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -like $Package}     | Remove-AppxProvisionedPackage -Online
    }
}
#endregion

#region Disable Scheduled Tasks

# This section is for disabling scheduled tasks.  If you find a task that should not be disabled
# comment or delete from the "SchTaskList.txt" file.
If (Test-Path .\Win10_1909_SchTaskList.txt)
{
    $SchTasksList = Get-Content .\Win10_1909_SchTaskList.txt
}
If ($SchTasksList.count -gt 0)
{
    $EnabledScheduledTasks = Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
    Foreach ($Item in $SchTasksList)
    {
        $Task = (($Item -split ":")[0]).Trim()
        $EnabledScheduledTasks | Where-Object { $_.TaskName -like "*$Task*" } | Disable-ScheduledTask
    }
}
#endregion

#region Customize Default User Profile
# Apply appearance customizations to default user registry hive, then close hive file

If (Test-Path .\Win10_1909_DefaultUserSettings.txt)
{
    $DefaultUserSettings = Get-Content .\Win10_1909_DefaultUserSettings.txt
}
If ($DefaultUserSettings.count -gt 0)
{
    Foreach ($Item in $DefaultUserSettings)
    {
        Start-Process C:\Windows\System32\Reg.exe -ArgumentList "$Item" -Wait 
    }
}
#endregion

#region Disable Windows Traces
If (Test-Path .\Win10_1909_ServicesAutologgersDisable.txt)
{
    $DisableAutologgers = Get-Content .\Win10_1909_ServicesAutologgersDisable.txt
}

If ($DisableAutologgers.count -gt 0)
{
    Foreach ($Item in $DisableAutologgers)
    {
        Write-Host "Processing $Item"
        New-ItemProperty -Path "$Item" -Name "Start" -PropertyType "DWORD" -Value "0" -Force
    }
}
#endregion

#region Local Group Policy Settings
# - This code does not:
#   * set a lock screen image.
#   * change the "Root Certificates Update" policy.
#   * change the "Enable Windows NTP Client" setting.
#   * set the "Select when Quality Updates are received" policy

if (Test-Path (Join-Path $PSScriptRoot "LGPO\LGPO.exe")) 
{
    Start-Process (Join-Path $PSScriptRoot "LGPO\LGPO.exe") -ArgumentList "/g $((Join-Path $PSScriptRoot "LGPO\."))" -Wait
}
#endregion

#region Disable Services
#################### BEGIN: DISABLE SERVICES section ###########################
If (Test-Path .\Win10_1909_ServicesDisable.txt)
 
{
    $ServicesToDisable = Get-Content .\Win10_1909_ServicesDisable.txt
}

If ($ServicesToDisable.count -gt 0)
{
    Foreach ($Item in $ServicesToDisable)
    {
        Write-Host "Processing $Item"
        Stop-Service $Item -Force -ErrorAction SilentlyContinue
        Set-Service $Item -StartupType Disabled 
        #New-ItemProperty -Path "$Item" -Name "Start" -PropertyType "DWORD" -Value "4" -Force
    }
}
#endregion

#region Disk Cleanup
#################### BEGIN: DISK CLEANUP section ###########################


# Disk Cleanup Wizard automation (Cleanmgr.exe /SAGESET:11)
# If you prefer to skip a particular disk cleanup category, edit the "Win10_1909_DiskCleanRegSettings.txt"
If (Test-Path .\Win10_1909_DiskCleanRegSettings.txt)
{
    $DiskCleanupSettings = Get-Content .\Win10_1909_DiskCleanRegSettings.txt
}
If ($DiskCleanupSettings.count -gt 0)
{
    Foreach ($Item in $DiskCleanupSettings)
    {
        Write-Host "Processing $Item"
        New-ItemProperty -Path "$Item" -Name "StateFlags0011" -PropertyType "DWORD" -Value "2" -Force
    }
}
Start-Process C:\Windows\System32\Cleanmgr.exe -ArgumentList "SAGERUN:11" -Wait
#endregion

#region Network Optimization
# LanManWorkstation optimizations
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name "DisableBandwidthThrottling" -PropertyType "DWORD" -Value "1" -Force
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name "FileInfoCacheEntriesMax" -PropertyType "DWORD" -Value "1024" -Force
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name "DirectoryCacheEntriesMax" -PropertyType "DWORD" -Value "1024" -Force
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name "FileNotFoundCacheEntriesMax" -PropertyType "DWORD" -Value "1024" -Force
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name "DormantFileLimit" -PropertyType "DWORD" -Value "256" -Force

# NIC Advanced Properties performance settings for network biased environments
Set-NetAdapterAdvancedProperty -DisplayName "Send Buffer Size" -DisplayValue 4MB

<# Note that the above setting is for a Microsoft Hyper-V VM.  You can adjust these values in your environment...
by querying in PowerShell using Get-NetAdapterAdvancedProperty, and then adjusting values using the...
Set-NetAdapterAdvancedProperty command.
#>
#endregion

#region
# ADDITIONAL DISK CLEANUP
# Delete not in-use files in locations C:\Windows\Temp and %temp%
# Also sweep and delete *.tmp, *.etl, *.evtx (not in use==not needed)

$FilesToRemove = Get-ChildItem -Path c:\ -Include *.tmp, *.etl, *.evtx -Recurse -Force -ErrorAction SilentlyContinue
$FilesToRemove | Remove-Item -ErrorAction SilentlyContinue

# Delete not in-use anything in the C:\Windows\Temp folder
Remove-Item -Path $env:windir\Temp\* -Recurse -Force -ErrorAction SilentlyContinue

# Delete not in-use anything in your %temp% folder
Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
#endregion

Add-Type -AssemblyName PresentationFramework
$Answer = [System.Windows.MessageBox]::Show("Reboot to make changes effective?", "Restart Computer", "YesNo", "Question")
Switch ($Answer)
{
    "Yes"   { Write-Warning "Restarting Computer in 15 Seconds"; Start-sleep -seconds 15; Restart-Computer -Force }
    "No"    { Write-Warning "A reboot is required for all changed to take effect" }
    Default { Write-Warning "A reboot is required for all changed to take effect" }
}

########################  END OF SCRIPT  ########################
