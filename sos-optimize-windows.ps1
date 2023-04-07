
param(
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Clear Existing GPOs: Clears Group Policy Objects settings.")]
    [bool]$cleargpos = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Install Windows Updates: Installs updates to the system.")]
    [bool]$installupdates = $true,
    [Parameter(Mandatory = $false, HelpMessage="STIGs: Adobe Acrobat Reader/Pro DC: Implements the Adobe Acrobat Reader STIGs.")]
    [bool]$adobe = $true,
    [Parameter(Mandatory = $false, HelpMessage="STIGs: Firefox: Implements the FireFox STIG.")]
    [bool]$firefox = $true,
    [Parameter(Mandatory = $false, HelpMessage="STIGs: Google Chrome: Implements the Google Chrome STIG.")]
    [bool]$chrome = $true,
    [Parameter(Mandatory = $false, HelpMessage="STIGs: Internet Explorer 11: Implements the Internet Explorer 11 STIG.")]
    [bool]$IE11 = $true,
    [Parameter(Mandatory = $false, HelpMessage="STIGs: Microsoft Edge: Implements the Microsoft Chromium Edge STIG.")]
    [bool]$edge = $true,
    [Parameter(Mandatory = $false, HelpMessage="STIGs: Microsoft .Net Framework: Implements the Dot Net 4 STIG.")]
    [bool]$dotnet = $true,
    [Parameter(Mandatory = $false, HelpMessage="STIGs: Microsoft Office: Implements the Microsoft Office Related STIGs.")]
    [bool]$office = $true,
    [Parameter(Mandatory = $false, HelpMessage="STIGs: Microsoft Onedrive: Implements the Onedrive STIGs.")]
    [bool]$onedrive = $true,
    [Parameter(Mandatory = $false, HelpMessage="STIGs: Oracle JRE 8: Implements the Oracle Java JRE 8 STIG.")]
    [bool]$java = $true,
    [Parameter(Mandatory = $false, HelpMessage="STIGs: Windows 10/11: Implements the Windows Desktop STIGs.")]
    [bool]$windows = $true,
    [Parameter(Mandatory = $false, HelpMessage="STIGs: Windows Defender Antivirus: Implements the Windows Defender STIG.")]
    [bool]$defender = $true,
    [Parameter(Mandatory = $false, HelpMessage="STIGs: Windows Firewall: Implements the Windows Firewall STIG.")]
    [bool]$firewall = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: General Mitigations: Implements General Best Practice Mitigations.")]
    [bool]$mitigations = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Windows Defender Hardening: Implements and Hardens Windows Defender Beyond STIG Requirements.")]
    [bool]$defenderhardening = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: PowerShell Hardening: Implements PowerShell Hardening and Logging.")]
    [bool]$pshardening = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: SSl Hardening: Implements SSL Hardening.")]
    [bool]$sslhardening = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: SMB Hardening: Hardens SMB Client and Server Settings.")]
    [bool]$smbhardening = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Applocker Hardening: Installs and Configures Applocker (In Audit Only Mode).")]
    [bool]$applockerhardening = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Harden Bitlocker Implementation.")]
    [bool]$bitlockerhardening = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Remove Bloatware: Removes unnecessary programs and features from the system.")]
    [bool]$removebloatware = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Disable Telemetry: Disables data collection and telemetry.")]
    [bool]$disabletelemetry = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Privacy Configurations: Makes changes to improve privacy.")]
    [bool]$privacy = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Image Cleanup: Cleans up unneeded files from the system")]
    [bool]$imagecleanup = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Nessus PID 63155: Resolves Unquoted System Strings in Path")]
    [bool]$nessusPID = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Sysmon Configurations: Installs and configures sysmon to improve auditing capabilities.")]
    [bool]$sysmon = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Enable Disk Compression: Compresses the system disk.")]
    [bool]$diskcompression = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: EMET: Implements STIG Requirements and Hardening for EMET on Windows 7 Systems.")]
    [bool]$emet = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Update Optimizations: Changes the way updates are managed and improved on the system.")]
    [bool]$updatemanagement = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Enable Device Guard: Enables Device Guard Hardening.")]
    [bool]$deviceguard = $true,
    [Parameter(Mandatory = $false, HelpMessage="SoS Configurations: Browser Configurations: Optimizes the system's web browsers.")]
    [bool]$sosbrowsers = $true
    
)

######SCRIPT FOR FULL INSTALL AND CONFIGURE ON STANDALONE MACHINE#####
#Continue on error
$ErrorActionPreference = 'silentlycontinue'

#Require elivation for script run
#Requires -RunAsAdministrator

#Set Directory to PSScriptRoot
if ((Get-Location).Path -NE $PSScriptRoot) { Set-Location $PSScriptRoot }

$paramscheck = $cleargpos, $installupdates, $adobe, $firefox, $chrome, $IE11, $edge, $dotnet, $office, $onedrive, $java, $windows, $defender, $firewall, $mitigations, $defenderhardening, $pshardening, $sslhardening, $smbhardening, $applockerhardening, $bitlockerhardening, $removebloatware, $disabletelemetry, $privacy, $imagecleanup, $nessusPID, $sysmon, $diskcompression, $emet, $updatemanagement, $deviceguard, $sosbrowsers

# run a warning if no options are set to true
if ($paramscheck | Where-Object { $_ -eq $false } | Select-Object -Count -EQ $params.Count) {
    Write-Error "No Options Were Selected. Exiting..."
    Exit
}

# if any parameters are set to true take a restore point
$date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$scriptName = $MyInvocation.MyCommand.Name
if ($paramscheck | Where-Object { $_ } | Select-Object) {
    $freespace = (Get-WmiObject -class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq 'C:' }).FreeSpace
    $minfreespace = 10000000000 #10GB
    if ($freespace -gt $minfreespace) {
        Write-Host "Taking a Restore Point Before Continuing...."
        $job = Start-Job -Name Take Restore Point -ScriptBlock {
            New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name 'SystemRestorePointCreationFrequency' -PropertyType DWORD -Value 0 -Force
            Checkpoint-Computer -Description "RestorePoint $scriptName $date" -RestorePointType "MODIFY_SETTINGS"
        }
        Wait-Job -Job $job
    }
    else {
        Write-Output "Not enough disk space to create a restore point. Current free space: $(($freespace/1GB)) GB"
    }
}

# Install Local Group Policy if Not Already Installed
if ($paramscheck | Where-Object { $_ } | Select-Object) {
    Start-Job -Name InstallGPOPackages -ScriptBlock {
        foreach ($F in (Get-ChildItem "$env:SystemRoot\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum").FullName) {
            if ((dism /online /get-packages | where-object { $_.name -like "*Microsoft-Windows-GroupPolicy-ClientTools*" }).count -eq 0) {
                dism /Online /NoRestart /Add-Package:$F
            }
        }

        foreach ($F in (Get-ChildItem "$env:SystemRoot\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum").FullName) {
            if ((dism /online /get-packages | where-object { $_.name -like "*Microsoft-Windows-GroupPolicy-ClientExtensions*" }).count -eq 0) {
                dism /Online /NoRestart /Add-Package:$F
            }
        }
    }
}

#GPO Configurations
function Import-GPOs([string]$gposdir) {
    Write-Host "Importing Group Policies from $gposdir ..." -ForegroundColor Green
    Foreach ($gpoitem in Get-ChildItem $gposdir) {
        Write-Host "Importing $gpoitem GPOs..." -ForegroundColor White
        $gpopath = "$gposdir\$gpoitem"
        #Write-Host "Importing $gpo" -ForegroundColor White
        .\Files\LGPO\LGPO.exe /g $gpopath > $null 2>&1
        #Write-Host "Done" -ForegroundColor Green
    }
}

if ($cleargpos -eq $true) {
    Write-Host "Removing Existing Local GPOs" -ForegroundColor Green
    #Remove and Refresh Local Policies
    Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicy" | Out-Null
    Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicyUsers" | Out-Null
    secedit /configure /cfg "$env:WinDir\inf\defltbase.inf" /db defltbase.sdb /verbose | Out-Null
    gpupdate /force | Out-Null
}
else {
    Write-Output "The Clear Existing GPOs Section Was Skipped..."
}

if ($installupdates -eq $true) {
    Write-Host "Installing the Latest Windows Updates" -ForegroundColor Green
    #Install PowerShell Modules
    Copy-Item -Path .\Files\"PowerShell Modules"\* -Destination C:\Windows\System32\WindowsPowerShell\v1.0\Modules -Force -Recurse
    #Unblock New PowerShell Modules
    Get-ChildItem C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\ -recurse | Unblock-File
    #Install PSWindowsUpdate
    Import-Module -Name PSWindowsUpdate -Force -Global 

    #Install Latest Windows Updates
    Start-Job -Name "Windows Updates" -ScriptBlock {
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll; Get-WuInstall -AcceptAll -IgnoreReboot; Get-WuInstall -AcceptAll -Install -IgnoreReboot
    }
}
else {
    Write-Output "The Install Update Section Was Skipped..."
}

if ($adobe -eq $true) {
    Write-Host "Implementing the Adobe STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Adobe"

    Start-Job -Name "Adobe Reader DC STIG" -ScriptBlock {
        #Adobe Reader DC STIG
        New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cCloud -Force
        New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cDefaultLaunchURLPerms -Force
        New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cServices -Force
        New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cSharePoint -Force
        New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cWebmailProfiles -Force
        New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cWelcomeScreen -Force
        Set-ItemProperty -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\Installer" -Name DisableMaintenance -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bAcroSuppressUpsell -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bDisablePDFHandlerSwitching -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bDisableTrustedFolders -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bDisableTrustedSites -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bEnableFlash -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bEnhancedSecurityInBrowser -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bEnhancedSecurityStandalone -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bProtectedMode -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name iFileAttachmentPerms -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name iProtectedView -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" -Name bAdobeSendPluginToggle -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name iURLPerms -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name iUnknownURLPerms -Type "DWORD" -Value 3 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bToggleAdobeDocumentServices -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bToggleAdobeSign -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bTogglePrefsSync -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bToggleWebConnectors -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bUpdater -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" -Name bDisableSharePointFeatures -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" -Name bDisableWebmail -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" -Name bShowWelcomeScreen -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" -Name DisableMaintenance -Type "DWORD" -Value 1 -Force
    }
}
else {
    Write-Output "The Adobe Section Was Skipped..."
}

if ($firefox -eq $true) {
    Write-Host "Implementing the FireFox STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\FireFox"
    Import-GPOs -gposdir ".\Files\GPOs\SoS\FireFox"

    Write-Host "simeononsecurity/FireFox-STIG-Script" -ForegroundColor Green
    Write-Host "https://github.com/simeononsecurity/FireFox-STIG-Script" -ForegroundColor Green 

    #https://www.itsupportguides.com/knowledge-base/tech-tips-tricks/how-to-customise-firefox-installs-using-mozilla-cfg/
    $firefox64 = "C:\Program Files\Mozilla Firefox"
    $firefox32 = "C:\Program Files (x86)\Mozilla Firefox"
    Write-Host "Installing Firefox Configurations - Please Wait." -ForegroundColor White
    Write-Host "Window will close after install is complete" -ForegroundColor White
    If (Test-Path -Path $firefox64) {
        Copy-Item -Path .\Files\"FireFox Configuration Files"\defaults -Destination $firefox64 -Force -Recurse
        Copy-Item -Path .\Files\"FireFox Configuration Files"\mozilla.cfg -Destination $firefox64 -Force
        Copy-Item -Path .\Files\"FireFox Configuration Files"\local-settings.js -Destination $firefox64 -Force 
        Write-Host "Firefox 64-Bit Configurations Installed" -ForegroundColor Green
    }
    Else {
        Write-Host "FireFox 64-Bit Is Not Installed" -ForegroundColor Red
    }
    If (Test-Path -Path $firefox32) {
        Copy-Item -Path .\Files\"FireFox Configuration Files"\defaults -Destination $firefox32 -Force -Recurse
        Copy-Item -Path .\Files\"FireFox Configuration Files"\mozilla.cfg -Destination $firefox32 -Force
        Copy-Item -Path .\Files\"FireFox Configuration Files"\local-settings.js -Destination $firefox32 -Force 
        Write-Host "Firefox 32-Bit Configurations Installed" -ForegroundColor Green
    }
    Else {
        Write-Host "FireFox 32-Bit Is Not Installed" -ForegroundColor Red
    }
}
else {
    Write-Output "The FireFox Section Was Skipped..."
}

if ($chrome -eq $true) {
    Write-Host "Implementing the Google Chrome STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Chrome"
}
else {
    Write-Output "The Google Chrome Section Was Skipped..."
}

if ($IE11 -eq $true) {
    Write-Host "Implementing the Internet Explorer 11 STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\IE11"
}
else {
    Write-Output "The Internet Explorer 11 Section Was Skipped..."
}

if ($edge -eq $true) {
    Write-Host "Implementing the Microsoft Edge STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Edge"

    #InPrivate browsing in Microsoft Edge must be disabled.
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowInPrivate" -Type "DWORD" -Value 0 -Force
    #Windows 10 must be configured to prevent Microsoft Edge browser data from being cleared on exit.
    New-Item -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\" -Name "Privacy" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Privacy" -Name ClearBrowsingHistoryOnExit -Type "DWORD" -Value 0 -Force
}
else {
    Write-Output "The Microsoft Edge Section Was Skipped..."
}

if ($dotnet -eq $true) {
    Write-Host "Implementing the Dot Net Framework STIGs" -ForegroundColor Green
    #SimeonOnSecurity - Microsoft .Net Framework 4 STIG Script
    #https://github.com/simeononsecurity
    #https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_DotNet_Framework_4-0_V1R9_STIG.zip
    #https://docs.microsoft.com/en-us/dotnet/framework/tools/caspol-exe-code-access-security-policy-tool

    Write-Host "Implementing simeononsecurity/.NET-STIG-Script" -ForegroundColor Green
    Write-Host "https://github.com/simeononsecurity/.NET-STIG-Script" -ForegroundColor Green 

    #Setting Netframework path variables
    $NetFramework32 = "C:\Windows\Microsoft.NET\Framework"
    $NetFramework64 = "C:\Windows\Microsoft.NET\Framework64"

    Write-Host "Beginning .NET STIG Script" -ForegroundColor Green

    #Vul ID: V-7055	   	Rule ID: SV-7438r3_rule	   	STIG ID: APPNET0031
    #Removing registry value
    If (Test-Path -Path "HKLM:\Software\Microsoft\StrongName\Verification") {
        Remove-Item "HKLM:\Software\Microsoft\StrongName\Verification" -Recurse -Force
        Write-Host ".Net StrongName Verification Registry Removed"
    } 
    Else {
        Write-Host ".Net StrongName Verification Registry Does Not Exist" -ForegroundColor Green
    }

    #Vul ID: V-7061	   	Rule ID: SV-7444r3_rule   	STIG ID: APPNET0046
    #The Trust Providers Software Publishing State must be set to 0x23C00.
    New-PSDrive HKU Registry HKEY_USERS | Out-Null
    ForEach ($UserSID in (Get-ChildItem "HKU:\")) {
        Write-Output $UserSID.Name | ConvertFrom-String -Delimiter "\\" -PropertyNames "PATH", "SID" | Set-Variable -Name "SIDs"
        ForEach ($SID in $SIDs.SID) {
            #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
            If (Test-Path -Path "HKU:\$SID\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\State") {
                Set-ItemProperty -Path "HKU:\$SID\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\" -Name "State" -Value "0x23C00" -Force | Out-Null
                Write-Host "Set Trust Providers Software Publishing State to 146432/0x23C00 for SID $SID" -ForegroundColor White
            }
            Else {
                New-Item -Path "HKU:\$SID\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\" -Name "State" -Force | Out-Null
                New-ItemProperty -Path "HKU:\$SID\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\" -Name "State" -Value "0x23C00" -Force | Out-Null
                Write-Host "Set Trust Providers Software Publishing State to 146432/0x23C00 for SID $SID" -ForegroundColor White
            }
        }
    }
    [gc]::collect()


    <#
    Creating secure configuration Function. It needs to be called in the
    two foreach loops as it has to touch every config file in each
    .net framework version folder

    Function Set-SecureConfig {
        param (
            $VersionPath,
            $SecureMachineConfigPath
        )
        
        #Declaration and error prevention
        $SecureMachineConfig = $Null
        $MachineConfig = $Null
        [system.gc]::Collect() 
        
        #Getting Secure Machine.Configs
        $SecureMachineConfig = [xml](Get-Content $SecureMachineConfigPath)
            
        #Write-Host "Still using test path at $(Get-CurrentLine)"
        #$MachineConfigPath = "C:\Users\hiden\Desktop\NET-STIG-Script-master\Files\secure.machine - Copy.config"
        $MachineConfigPath = "$VersionPath"
        $MachineConfig = [xml](Get-Content $MachineConfigPath)
        #Ensureing file is closed
        [IO.File]::OpenWrite((Resolve-Path $MachineConfigPath).Path).close()

        #Apply Machine.conf Configurations
        #Pulled XML assistance from https://stackoverflow.com/questions/9944885/powershell-xml-importnode-from-different-file
        #Pulled more XML details from http://www.maxtblog.com/2012/11/add-from-one-xml-data-to-another-existing-xml-file/
    
        Write-Host "Begining work on $MachineConfigPath..." -ForegroundColor White
    
        # Do out. Automate each individual childnode for infinite nested. Currently only goes two deep
        $SecureChildNodes = $SecureMachineConfig.configuration | Get-Member | Where-Object MemberType -match "^Property" | Select-Object -ExpandProperty Name
        $MachineChildNodes = $MachineConfig.configuration | Get-Member | Where-Object MemberType -match "^Property" | Select-Object -ExpandProperty Name


        #Checking if each secure node is present in the XML file
        ForEach ($SecureChildNode in $SecureChildNodes) {
            #If it is not present, easy day. Add it in.
            If ($SecureChildNode -notin $MachineChildNodes) {
                #Adding node from the secure.machine.config file and appending it to the XML file
                $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode, $true)
                $MachineConfig.DocumentElement.AppendChild($NewNode) | Out-Null
                #Saving changes to XML file
                $MachineConfig.Save($MachineConfigPath)
            }
            Elseif ($MachineConfig.configuration.$SecureChildNode -eq "") {
                #Turns out element sometimes is present but entirely empty. If that is the case we need to remove it
                # and add what we want         
                $MachineConfig.configuration.ChildNodes | Where-Object name -eq $SecureChildNode | ForEach-Object { $MachineConfig.configuration.RemoveChild($_) } | Out-Null
                $MachineConfig.Save($MachineConfigPath)
                #Adding node from the secure.machine.config file and appending it to the XML file            
                $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode, $true)
                $MachineConfig.DocumentElement.AppendChild($NewNode) | Out-Null
                #Saving changes to XML file
                $MachineConfig.Save($MachineConfigPath)
            }
            Else {
                
                #If it is present... we have to check if the node contains the elements we want.
                #Going through each node in secure.machine.config for comparison
                $SecureElements = $SecureMachineConfig.configuration.$SecureChildNode | Get-Member | Where-Object MemberType -Match "^Property" | Where-object Name -notmatch "#comment" | Select-Object -Expandproperty Name        
                #Pull the Machine.config node and childnode and get the data properties for comparison
                $MachineElements = $MachineConfig.configuration.$SecureChildNode | Get-Member | Where-Object MemberType -Match "^Property" | Where-object Name -notmatch "#comment" | Select-Object -Expandproperty Name

                #I feel like there has got to be a better way to do this as we're three loops deep
                foreach ($SElement in $SecureElements) {
                    #Comparing Element pulled earlier against Machine Elements.  If it's not present we will add it in
                    If ($SElement -notin $MachineElements) {
                        #Adding in element that is not present
                        If ($SecureMachineConfig.configuration.$SecureChildNode.$SElement -NE "") {
                            $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode.$SElement, $true)
                            $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                            #Saving changes to XML file
                            $MachineConfig.Save($MachineConfigPath)
                        }
                        Else {
                            #This is for when the value declared is empty.
                            $NewNode = $MachineConfig.CreateElement("$SElement")                     
                            $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                            #Saving changes to XML file
                            $MachineConfig.Save($MachineConfigPath)
                        }
                    }
                    Else {
                        $OldNode = $MachineConfig.SelectSingleNode("//$SElement")
                        $MachineConfig.configuration.$SecureChildNode.RemoveChild($OldNode) | Out-Null
                        $MachineConfig.Save($MachineConfigPath)
                        If ($SecureMachineConfig.configuration.$SecureChildNode.$SElement -EQ "") {
                            $NewElement = $MachineConfig.CreateElement("$SElement")
                            $MachineConfig.configuration.$SecureChildNode.AppendChild($NewElement) | Out-Null
                        }
                        Else {
                            $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode.$SElement, $true)
                            $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                        }
                    
                        #Saving changes to XML file
                        $MachineConfig.Save($MachineConfigPath)               
                    }#End else
                }#Foreach Element within SecureElements
            }#Else end for an if statement checking if the desired childnode is in the parent file
        }#End of iterating through SecureChildNodes
    
        Write-Host "Merge Complete" -ForegroundColor White
    }
    #>

    # .Net 32-Bit
    ForEach ($DotNetVersion in (Get-ChildItem $netframework32 -Directory)) {
        Write-Host ".Net 32-Bit $DotNetVersion Is Installed" -ForegroundColor Green
        #Starting .net exe/API to pass configuration Arguments
        If (Test-Path "$($DotNetVersion.FullName)\caspol.exe") {
            Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -WindowStyle Hidden
            Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -WindowStyle Hidden 
            # Comment lines above and uncomment lines below to see output
            #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -NoNewWindow
            #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -NoNewWindow
            Write-Host "Set CAS policy for $DotNetVersion 32-Bit" -ForegroundColor White
        }
        #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
        If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -Value "0" -Force | Out-Null
            Write-Host "Disabled Strong Name Bypass for $DotNetVersion 32-Bit" -ForegroundColor White
        }
        Else {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\" -Name ".NETFramework" -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0" -Force | Out-Null
            Write-Host "Disabled Strong Name Bypass for $DotNetVersion 32-Bit" -ForegroundColor White
        }
        #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
        If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\SchUseStrongCrypto") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -Value "1" -Force | Out-Null
            Write-Host "Enforced Strong Crypto for $DotNetVersion 32-Bit" -ForegroundColor White
        }
        Else {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name "$DotNetVersion" -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1" -Force | Out-Null
            Write-Host "Enforced Strong Crypto for $DotNetVersion 32-Bit" -ForegroundColor White
        }

        <# Source for specifying configs for specific .Net versions
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/enforcefipspolicy-element (2.0 or higher)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/loadfromremotesources-element (4.0 or higher)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/netfx40-legacysecuritypolicy-element (4.0 or higher)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/etwenable-element (Doesn't specify. Assuming 3.0 or higher because it mentions Vista)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/network/defaultproxy-element-network-settings (Doesn't specify.)

        
        #Ensuring .net version has machine.config
        If (Test-Path "$($DotNetVersion.FullName)\Config\Machine.config") {
            #.net Version testing.
            If (($DotNetVersion -Split "v" )[1] -ge 2) {
                #.net version testing.
                If (($DotNetVersion -Split "v" )[1] -ge 4) {
                    Write-Host ".Net version 4 or higher... Continuing with v4.0+ Machine.conf Merge..." -ForegroundColor White
                    Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath "$PSScriptRoot\Files\.Net Configuration Files\secure.machine-v4.config"
                }
                Else {
                    Write-Host ".Net version is less than 4... Continuing with v2.0+ Machine.conf Merge..." -ForegroundColor White
                    Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath "$PSScriptRoot\Files\.Net Configuration Files\secure.machine-v2.config"
                }
            }
            Else {
                Write-Host ".Net version is less than 2... Skipping Machine.conf Merge..." -ForegroundColor Yellow
            }#End dotnet version test
        }
        Else {
            Write-Host "No Machine.Conf file exists for .Net version $DotNetVersion" -ForegroundColor Red
        }#End testpath
        #>
    }
    

    # .Net 64-Bit
    ForEach ($DotNetVersion in (Get-ChildItem $netframework64 -Directory)) {  
        Write-Host ".Net 64-Bit $DotNetVersion Is Installed" -ForegroundColor Green
        #Starting .net exe/API to pass configuration Arguments
        If (Test-Path "$($DotNetVersion.FullName)\caspol.exe") {
            Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -WindowStyle Hidden
            Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -WindowStyle Hidden 
            # Comment lines above and uncomment lines below to see output
            #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -NoNewWindow
            #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -NoNewWindow
            Write-Host "Set CAS policy for $DotNetVersion 64-Bit" -ForegroundColor White
        }
        #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
        If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -Value "0" -Force | Out-Null
            Write-Host "Disabled Strong Name Bypass for $DotNetVersion 64-Bit" -ForegroundColor White
        }
        Else {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\" -Name ".NETFramework" -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0" -Force | Out-Null
            Write-Host "Disabled Strong Name Bypass for $DotNetVersion 64-Bit" -ForegroundColor White
        }
        #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
        If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -Value "1" -Force | Out-Null
            Write-Host "Enforced Strong Crypto for $DotNetVersion 64-Bit" -ForegroundColor White
        }
        Else {
            New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\" -Name "$DotNetVersion" -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1" -Force | Out-Null
            Write-Host "Enforced Strong Crypto for $DotNetVersion 64-Bit" -ForegroundColor White
        }

        <# Source for specifying configs for specific .Net versions
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/enforcefipspolicy-element (2.0 or higher)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/loadfromremotesources-element (4.0 or higher)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/netfx40-legacysecuritypolicy-element (4.0 or higher)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/etwenable-element (Doesn't specify. Assuming 3.0 or higher because it mentions Vista)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/network/defaultproxy-element-network-settings (Doesn't specify.)

        
        #Ensuring current version has a machine.config to use
        If (Test-Path "$($DotNetVersion.FullName)\Config\Machine.config") {
            #version testing
            If (($DotNetVersion -Split "v" )[1] -ge 2) {
                #More version testing.
                If (($DotNetVersion -Split "v" )[1] -ge 4) {
                    Write-Host ".Net version 4 or higher... Continuing with v4.0+ Machine.conf Merge..." -ForegroundColor White
                    Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath "$PSScriptRoot\Files\.Net Configuration Files\secure.machine-v4.config"
                }
                Else {
                    Write-Host ".Net version is less than 4... Continuing with v2.0+ Machine.conf Merge..." -ForegroundColor White
                    Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath "$PSScriptRoot\Files\.Net Configuration Files\secure.machine-v2.config"
                }
            }
            Else {
                Write-Host ".Net version is less than 2... Skipping Machine.conf Merge..." -ForegroundColor Yellow
            }#End .net version test
        }
        Else {
            Write-Host "No Machine.Conf file exists for .Net version $DotNetVersion" -ForegroundColor Red
        }#End testpath
            #>
    }
}
else {
    Write-Output "The Dot Net Framework Section Was Skipped..."
}

if ($office -eq $true) {
    Write-Host "Implementing the Microsoft Office STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Office"
}
else {
    Write-Output "The Microsoft Office Section Was Skipped..."
}

if ($onedrive -eq $true) {
    Write-Host "Implementing the Microsoft OneDrive STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\SoS\Onedrive"
}
else {
    Write-Output "The OneDrive Section Was Skipped..."
}

if ($java -eq $true) {
    Write-Host "Implementing the Oracle Java JRE 8 STIGs" -ForegroundColor Green
    Write-Host "Implementing simeononsecurity/JAVA-STIG-Script" -ForegroundColor Green
    Write-Host "https://github.com/simeononsecurity/JAVA-STIG-Script" -ForegroundColor Green 

    #https://gist.github.com/MyITGuy/9628895
    #http://stu.cbu.edu/java/docs/technotes/guides/deploy/properties.html

    #<Windows Directory>\Sun\Java\Deployment\deployment.config
    #- or -
    #<JRE Installation Directory>\lib\deployment.config

    if (Test-Path -Path "C:\Windows\Sun\Java\Deployment\deployment.config") {
        Write-Host "JAVA Deployment Config Already Installed" -ForegroundColor Green
    }
    else {
        Write-Host "Installing JAVA Deployment Config...." -ForegroundColor Green
        Mkdir "C:\Windows\Sun\Java\Deployment\"
        Copy-Item -Path .\Files\"JAVA Configuration Files"\deployment.config -Destination "C:\Windows\Sun\Java\Deployment\" -Force
        Write-Host "JAVA Configs Installed" -ForegroundColor White
    }
    if (Test-Path -Path "C:\Windows\Java\Deployment\") {
        Write-Host "JAVA Configs Already Deployed" -ForegroundColor Green
    }
    else {
        Write-Host "Installing JAVA Configurations...." -ForegroundColor Green
        Mkdir "C:\Windows\Java\Deployment\"
        Copy-Item -Path .\Files\"JAVA Configuration Files"\deployment.properties -Destination "C:\Windows\Java\Deployment\" -Force
        Copy-Item -Path .\Files\"JAVA Configuration Files"\exception.sites -Destination "C:\Windows\Java\Deployment\" -Force
        Write-Host "JAVA Configs Installed" -ForegroundColor White
    }
}
else {
    Write-Output "The Oracle Java JRE 8 Section Was Skipped..."
}

if ($windows -eq $true) {
    Write-Host "Implementing the Windows 10/11 STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Windows"

    Write-Host "Implementing simeononsecurity/Windows-Audit-Policy" -ForegroundColor Green
    Write-Host "https://github.com/simeononsecurity/Windows-Audit-Policy" -ForegroundColor Green 

    New-Item -Force -ItemType "Directory" "C:\temp"
    Copy-Item $PSScriptRoot\files\auditing\auditbaseline.csv C:\temp\auditbaseline.csv 

    #Clear Audit Policy
    auditpol /clear /y

    #Enforce the Audit Policy Baseline
    auditpol /restore /file:C:\temp\auditbaseline.csv

    #Confirm Changes
    auditpol /list /user /v
    auditpol.exe /get /category:*

    #Basic authentication for RSS feeds over HTTP must not be used.
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer" -Name "Feeds" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Name "AllowBasicAuthInClear" -Type "DWORD" -Value 0 -Force
    #Check for publishers certificate revocation must be enforced.
    New-Item -Path "HKLM:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\" -Name "Software Publishing" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\Software Publishing" -Name State -Type "DWORD" -Value 146432 -Force
    New-Item -Path "HKCU:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\" -Name "Software Publishing" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\Software Publishing" -Name State -Type "DWORD" -Value 146432 -Force
    #AutoComplete feature for forms must be disallowed.
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "Main Criteria" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "Use FormSuggest" -Type "String" -Value no -Force
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\" -Name "Main Criteria" -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "Use FormSuggest" -Type "String" -Value no -Force
    #Turn on the auto-complete feature for user names and passwords on forms must be disabled.
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "FormSuggest PW Ask" -Type "String" -Value no -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "FormSuggest PW Ask" -Type "String" -Value no -Force
    #Windows 10 must be configured to prioritize ECC Curves with longer key lengths first.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "EccCurves" -Type "MultiString" -Value "NistP384 NistP256" -Force
    #Zone information must be preserved when saving attachments.
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "Main Criteria" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "SaveZoneInformation" -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "SaveZoneInformation" -Type "DWORD" -Value 2 -Force
    #Toast notifications to the lock screen must be turned off.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\" -Name "PushNotifications" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" -Name "NoToastApplicationNotificationOnLockScreen" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" -Name "NoToastApplicationNotificationOnLockScreen" -Type "DWORD" -Value 1 -Force
    #Windows 10 should be configured to prevent users from receiving suggestions for third-party or additional applications.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "CloudContent" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Type "DWORD" -Value 1 -Force
    #Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "AppPrivacy" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\" -Name "LetAppsActivateWithVoice" -Type "DWORD" -Value 2 -Force
    #The Windows Explorer Preview pane must be disabled for Windows 10.
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "Explorer" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoReadingPane" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoReadingPane" -Type "DWORD" -Value 1 -Force
    #The use of a hardware security device with Windows Hello for Business must be enabled.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "PassportForWork" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\" -Name "RequireSecurityDevice" -Type "DWORD" -Value 1 -Force
}
else {
    Write-Output "The Windows Desktop Section Was Skipped..."
}

if ($defender -eq $true) {
    Write-Host "Implementing the Windows Defender STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Defender"
}
else {
    Write-Output "The Windows Defender Section Was Skipped..."
}

if ($firewall -eq $true) {
    Write-Host "Implementing the Windows Firewall STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\FireWall"
}
else {
    Write-Output "The Windows Firewall Section Was Skipped..."
}

if ($mitigations -eq $true) {
    Write-Host "Implementing the General Vulnerability Mitigations" -ForegroundColor Green
    Start-Job -Name "Mitigations" -ScriptBlock {
        #####SPECTURE MELTDOWN#####
        #https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Type "DWORD" -Value 72 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type "DWORD" -Value 3 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -Type "String" -Value "1.0" -Force
    
        #Disable LLMNR
        #https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
        New-Item -Path "HKLM:\Software\policies\Microsoft\Windows NT\" -Name "DNSClient" -Force
        Set-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value 0 -Force
    
        #Disable TCP Timestamps
        netsh int tcp set global timestamps=disabled
    
        #Enable DEP
        BCDEDIT /set "{current}" nx OptOut
        Set-Processmitigation -System -Enable DEP
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableHHDEP" -Type "DWORD" -Value 0 -Force
    
        #Enable SEHOP
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Type "DWORD" -Value 0 -Force
    
        #Disable NetBIOS by updating Registry
        #http://blog.dbsnet.fr/disable-netbios-with-powershell#:~:text=Disabling%20NetBIOS%20over%20TCP%2FIP,connection%2C%20then%20set%20NetbiosOptions%20%3D%202
        $key = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
        Get-ChildItem $key | ForEach-Object { 
            Write-Host("Modify $key\$($_.pschildname)")
            $NetbiosOptions_Value = (Get-ItemProperty "$key\$($_.pschildname)").NetbiosOptions
            Write-Host("NetbiosOptions updated value is $NetbiosOptions_Value")
        }
        
        #Disable WPAD
        #https://adsecurity.org/?p=3299
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\" -Name "Wpad" -Force
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "Wpad" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Type "DWORD" -Value 1 -Force
    
        #Enable LSA Protection/Auditing
        #https://adsecurity.org/?p=3299
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" -Name "LSASS.exe" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Type "DWORD" -Value 8 -Force
    
        #Disable Windows Script Host
        #https://adsecurity.org/?p=3299
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\" -Name "Settings" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type "DWORD" -Value 0 -Force
        
        #Disable WDigest
        #https://adsecurity.org/?p=3299
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\Wdigest" -Name "UseLogonCredential" -Type "DWORD" -Value 0 -Force
    
        #Block Untrusted Fonts
        #https://adsecurity.org/?p=3299
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" -Name "MitigationOptions" -Type "QWORD" -Value "1000000000000" -Force
        
        #Disable Office OLE
        #https://adsecurity.org/?p=3299
        $officeversions = '16.0', '15.0', '14.0', '12.0'
        ForEach ($officeversion in $officeversions) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\" -Name "Security" -Force
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\" -Name "Security" -Force
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\Security\" -Name "ShowOLEPackageObj" -Type "DWORD" -Value "0" -Force
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\Security\" -Name "ShowOLEPackageObj" -Type "DWORD" -Value "0" -Force
        }
    
        #Disable Hibernate
        powercfg -h off
    }
}
else {
    Write-Output "The General Mitigations Section Was Skipped..."
}

if ($defenderhardening -eq $true) {
    Write-Host "Implementing Windows Defender Hardening Beyond STIGs" -ForegroundColor Green

    Import-GPOs -gposdir ".\Files\GPOs\SoS\WDAC"

    #Windows Defender Configuration Files
    New-Item -Path "C:\" -Name "Temp" -ItemType "directory" -Force | Out-Null; New-Item -Path "C:\temp\" -Name "Windows Defender" -ItemType "directory" -Force | Out-Null; Copy-Item -Path .\Files\"Windows Defender Configuration Files"\* -Destination "C:\temp\Windows Defender\" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null

    Start-Job -Name "Windows Defender Hardening" -ScriptBlock {
        #Enable Windows Defender Exploit Protection
        Set-ProcessMitigation -PolicyFilePath "C:\temp\Windows Defender\DOD_EP_V3.xml"

        #Enable Windows Defender Application Control
        #https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/select-types-of-rules-to-create
        Set-RuleOption -FilePath "C:\temp\Windows Defender\WDAC_V1_Recommended_Audit.xml" -Option 0

        #Windows Defender Hardening
        #https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSetting
        #Enable real-time monitoring
        Write-Host "Enable real-time monitoring"
        Set-MpPreference -DisableRealtimeMonitoring 0
        #Enable sample submission
        Write-Host "Enable sample submission"
        Set-MpPreference -SubmitSamplesConsent 2
        #Enable checking signatures before scanning
        Write-Host "Enable checking signatures before scanning"
        Set-MpPreference -CheckForSignaturesBeforeRunningScan 1
        #Enable behavior monitoring
        Write-Host "Enable behavior monitoring"
        Set-MpPreference -DisableBehaviorMonitoring 0
        #Enable IOAV protection
        Write-Host "Enable IOAV protection"
        Set-MpPreference -DisableIOAVProtection 0
        #Enable script scanning
        Write-Host "Enable script scanning"
        Set-MpPreference -DisableScriptScanning 0
        #Enable removable drive scanning
        Write-Host "Enable removable drive scanning"
        Set-MpPreference -DisableRemovableDriveScanning 0
        #Enable Block at first sight
        Write-Host "Enable Block at first sight"
        Set-MpPreference -DisableBlockAtFirstSeen 0
        #Enable potentially unwanted 
        Write-Host "Enable potentially unwanted apps"
        Set-MpPreference -PUAProtection Enabled
        #Schedule signature updates every 8 hours
        Write-Host "Schedule signature updates every 8 hours"
        Set-MpPreference -SignatureUpdateInterval 8
        #Enable archive scanning
        Write-Host "Enable archive scanning"
        Set-MpPreference -DisableArchiveScanning 0
        #Enable email scanning
        Write-Host "Enable email scanning"
        Set-MpPreference -DisableEmailScanning 0
        #Enable File Hash Computation
        Write-Host "Enable File Hash Computation"
        Set-MpPreference -EnableFileHashComputation 1
        #Enable Intrusion Prevention System
        Write-Host "Enable Intrusion Prevention System"
        Set-MpPreference -DisableIntrusionPreventionSystem $false
        #Enable Windows Defender Exploit Protection
        Write-Host "Enabling Exploit Protection"
        Set-ProcessMitigation -PolicyFilePath C:\temp\"Windows Defender"\DOD_EP_V3.xml
        #Set cloud block level to 'High'
        Write-Host "Set cloud block level to 'High'"
        Set-MpPreference -CloudBlockLevel High
        #Set cloud block timeout to 1 minute
        Write-Host "Set cloud block timeout to 1 minute"
        Set-MpPreference -CloudExtendedTimeout 50
        Write-Host "`nUpdating Windows Defender Exploit Guard settings`n" -ForegroundColor Green 
        #Enabling Controlled Folder Access and setting to block mode
        #Write-Host "Enabling Controlled Folder Access and setting to block mode"
        #Set-MpPreference -EnableControlledFolderAccess Enabled 
        #Enabling Network Protection and setting to block mode
        Write-Host "Enabling Network Protection and setting to block mode"
        Set-MpPreference -EnableNetworkProtection Enabled

        #Enable Cloud-delivered Protections
        #Set-MpPreference -MAPSReporting Advanced
        #Set-MpPreference -SubmitSamplesConsent SendAllSamples

        #Enable Windows Defender Attack Surface Reduction Rules
        #https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-attack-surface-reduction
        #https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
        #Block executable content from email client and webmail
        Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
        #Block all Office applications from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
        #Block Office applications from creating executable content
        Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
        #Block Office applications from injecting code into other processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
        #Block JavaScript or VBScript from launching downloaded executable content
        Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
        #Block execution of potentially obfuscated scripts
        Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
        #Block Win32 API calls from Office macros
        Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
        #Block executable files from running unless they meet a prevalence, age, or trusted list criterion
        Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions AuditMode
        #Use advanced protection against ransomware
        Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled
        #Block credential stealing from the Windows local security authority subsystem
        Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
        #Block process creations originating from PSExec and WMI commands
        Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions AuditMode
        #Block untrusted and unsigned processes that run from USB
        Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
        #Block Office communication application from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
        #Block Adobe Reader from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
        #Block persistence through WMI event subscription
        Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
    }
}
else {
    Write-Output "The Windows Defender Hardening Section Was Skipped..."
}

if ($pshardening -eq $true) {
    Write-Host "Implementing PowerShell Hardening Beyond STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\SoS\Powershell"

    Start-Job -Name "PowerShell Hardening" -ScriptBlock {
        #Disable Powershell v2
        Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -NoRestart
    
        #Enable PowerShell Logging
        #https://www.digitalshadows.com/blog-and-research/powershell-security-best-practices/
        #https://www.cyber.gov.au/acsc/view-all-content/publications/securing-powershell-enterprise
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\" -Name "Transcription" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Type "STRING" -Value "C:\PowershellLogs" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name "EnableScriptBlockLogging" -Type "DWORD" -Value "1" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\" -Name "EnableTranscripting" -Type "DWORD" -Value "1" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\" -Name "EnableInvocationHeader" -Type "DWORD" -Value "1" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Type "STRING" -Value "C:\PowershellLogs" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name "EnableScriptBlockLogging" -Type "DWORD" -Value "1" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\" -Name "EnableTranscripting" -Type "DWORD" -Value "1" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\" -Name "EnableInvocationHeader" -Type "DWORD" -Value "1" -Force
    
        #Prevent WinRM from using Basic Authentication
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Type "DWORD" -Value 0 -Force
    
        #WinRM Hardening
        #https://4sysops.com/archives/powershell-remoting-over-https-with-a-self-signed-ssl-certificate/
        #$Cert = New-SelfSignedCertificate -CertstoreLocation Cert:\LocalMachine\My -DnsName (cmd /c hostname) 
        #Export-Certificate -Cert $Cert -FilePath C:\temp\cert
        #Remove Previous WinRM Listeners
        #Get-ChildItem WSMan:\Localhost\listener | Where-Object -Property Keys -eq "Transport=HTTP" | Remove-Item -Recurse
        #Remove-Item -Path WSMan:\Localhost\listener\listener* -Recurse
        #Add New HTTPS (ONLY) Listener
        #New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $Cert.Thumbprint –Force
        #Start the service at boot
        #Set-Service -Name "WinRM" -StartupType Automatic -Status Running
        #Enable Firewall rule
        #New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Name "Windows Remote Management (HTTPS-In)" -Profile Private, Domain -LocalPort 5986 -Protocol TCP
        #Enable PSRemoting
        #Enable-PSRemoting -SkipNetworkProfileCheck -Force
    }
}
else {
    Write-Output "The PowerShell Hardening Section Was Skipped..."
}

if ($applockerhardening -eq $true) {
    Write-Host "Implementing Applocker Hardening Beyond STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\NSACyber\Applocker"
}
else {
    Write-Output "The Applocker Hardening Section Was Skipped..."
}

if ($bitlockerhardening -eq $true) {
    Write-Host "Implementing Bitlocker Hardening Beyond STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\NSACyber\Bitlocker"
}
else {
    Write-Output "The Bitlocker Hardening Section Was Skipped..."
}

if ($sslhardening -eq $true) {
    Write-Host "Implementing SSL Hardening Beyond STIGs" -ForegroundColor Green
    Start-Job -Name "SSL Hardening" -ScriptBlock {

        #Increase Diffie-Hellman key (DHK) exchange to 4096-bit
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Force 
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Force -Name ServerMinKeyBitLength -Type "DWORD" -Value 0x00001000
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Force -Name ClientMinKeyBitLength -Type "DWORD" -Value 0x00001000
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Force -Name Enabled -Type "DWORD" -Value 0x00000001
    
        #Disable RC2 cipher
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -Force 
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -Force 
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -Force 
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    
        #Disable RC4 cipher
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -Force
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -Force  
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -Force
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -Force  
        #New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
        #New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
        #New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
        #New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    
        #Disable DES cipher
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56" -Force
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Force  
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    
        #Disable 3DES (Triple DES) cipher
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Force
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168" -Force  
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168" -Force -Name Enabled -Type "DWORD" -Value 0x00000000       
    
        #Disable MD5 hash function
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Force
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    
        #Disable SHA1
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Force
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    
        #Disable null cipher
        #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Force
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    
        #Force not to respond to renegotiation requests
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Force -Name AllowInsecureRenegoClients -Type "DWORD" -Value 0x00000000
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Force -Name AllowInsecureRenegoServers -Type "DWORD" -Value 0x00000000
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Force -Name DisableRenegoOnServer -Type "DWORD" -Value 0x00000001
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Force -Name UseScsvForTls -Type "DWORD" -Value 0x00000001
    
        #Disable SSL v2
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"-Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force -Name Enabled -Type "DWORD" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Force -Name Enabled -Type "DWORD" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 1
    
        #Disable SSL v3
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"-Force
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force -Name Enabled -Type "DWORD" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force -Name Enabled -Type "DWORD" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 1
    
        #Enable TLS 1.0
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0x00000001
    
        #Enable DTLS 1.0
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" -Force
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" -Force -Name Enabled -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" -Force -Name Enabled -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    
        #Enable TLS 1.1
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force -Name Enabled -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force -Name Enabled -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    
        #Enable DTLS 1.1
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server" -Force
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client" -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server" -Force -Name Enabled -Type "DWORD" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client" -Force -Name Enabled -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    
        #Enable TLS 1.2
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force -Name Enabled -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force -Name Enabled -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    
        #Enable TLS 1.3
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force -Name Enabled -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Force -Name Enabled -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    
        #Enable DTLS 1.3
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server" -Force
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client" -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server" -Force -Name Enabled -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client" -Force -Name Enabled -Type "DWORD" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    
        #Enable Strong Authentication for .NET applications (TLS 1.2)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
    }
}
else {
    Write-Output "The SSL Hardening Section Was Skipped..."
}

if ($smbhardening -eq $true) {
    Write-Host "Implementing SMB Hardening Beyond STIGs" -ForegroundColor Green
    Start-Job -Name "SMB Optimizations and Hardening" -ScriptBlock {
        #https://docs.microsoft.com/en-us/windows/privacy/
        #https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
        #https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds_vdi-recommendations-1909
        #https://docs.microsoft.com/en-us/powershell/module/smbshare/set-smbserverconfiguration?view=win10-ps
        #SMB Optimizations
        Write-Output "SMB Optimizations"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DisableBandwidthThrottling" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "FileInfoCacheEntriesMax" -Type "DWORD" -Value 1024 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DirectoryCacheEntriesMax" -Type "DWORD" -Value 1024 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "FileNotFoundCacheEntriesMax" -Type "DWORD" -Value 2048 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type "DWORD" -Value 20 -Force
        Set-SmbServerConfiguration -EnableMultiChannel $true -Force 
        Set-SmbServerConfiguration -MaxChannelPerSession 16 -Force
        Set-SmbServerConfiguration -ServerHidden $False -AnnounceServer $False -Force
        Set-SmbServerConfiguration -EnableLeasing $false -Force
        Set-SmbClientConfiguration -EnableLargeMtu $true -Force
        Set-SmbClientConfiguration -EnableMultiChannel $true -Force
        
        #SMB Hardening
        Write-Output "SMB Hardening"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "RestrictAnonymousSAM" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" -Value 256 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RestrictAnonymous" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Type "DWORD" -Value 1 -Force
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart
        Set-SmbClientConfiguration -RequireSecuritySignature $True -Force
        Set-SmbClientConfiguration -EnableSecuritySignature $True -Force
        Set-SmbServerConfiguration -EncryptData $True -Force 
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force 
    }
}
else {
    Write-Output "The SMB Hardening Section Was Skipped..."
}

if ($removebloatware -eq $true) {
    Write-Host "Removing Windows Bloatware" -ForegroundColor Green
    Start-Job -Name "Remove Windows Bloatware" -ScriptBlock {
        #Removing Windows Bloatware
        Write-Host "Removing Bloatware"
        Write-Host "Removing Bloat Windows Apps"
        $WindowsApps = "*ACGMediaPlayer*", "*ActiproSoftwareLLC*", "*AdobePhotoshopExpress*", "*AdobeSystemsIncorporated.AdobePhotoshopExpress*", "*BubbleWitch3Saga*", "*CandyCrush*", "*CommsPhone*", "*ConnectivityStore*", "*Dolby*", "*Duolingo-LearnLanguagesforFree*", "*EclipseManager*", "*Facebook*", "*FarmHeroesSaga*", "*Flipboard*", "*HiddenCity*", "*Hulu*", "*LinkedInforWindows*", "*Microsoft.3dbuilder*", "*Microsoft.549981C3F5F10*", "*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*", "*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*", "*Microsoft.Appconnector*", "*Microsoft.Asphalt8Airborne*", "*Microsoft.BingNews*", "*Microsoft.BingWeather*", "*Microsoft.DrawboardPDF*", "*Microsoft.GamingApp*", "*Microsoft.GetHelp*", "*Microsoft.Getstarted*", "*Microsoft.MSPaint*", "*Microsoft.Messaging*", "*Microsoft.Microsoft3DViewer*", "*Microsoft.MicrosoftOfficeHub*", "*Microsoft.MicrosoftOfficeOneNote*", "*Microsoft.MicrosoftSolitaireCollection*", "*Microsoft.MicrosoftStickyNotes*", "*Microsoft.MixedReality.Portal*", "*Microsoft.OneConnect*", "*Microsoft.People*", "*Microsoft.Print3D*", "*Microsoft.SkypeApp*", "*Microsoft.Wallet*", "*Microsoft.Whiteboard*", "*Microsoft.WindowsAlarms*", "*Microsoft.WindowsCommunicationsApps*", "*Microsoft.WindowsFeedbackHub*", "*Microsoft.WindowsMaps*", "*Microsoft.WindowsSoundRecorder*", "*Microsoft.YourPhone*", "*Microsoft.ZuneMusic*", "*Microsoft.ZuneVideo*", "*Microsoft3DViewer*", "*MinecraftUWP*", "*Netflix*", "*Office.Sway*", "*OneCalendar*", "*OneNote*", "*PandoraMediaInc*", "*RoyalRevolt*", "*SpeedTest*", "*Sway*", "*Todos*", "*Twitter*", "*Viber*", "*WindowsScan*", "*Wunderlist*", "*bingsports*", "*empires*", "*spotify*", "*windowsphone*", "*xing*", "2FE3CB00.PicsArt-PhotoStudio", "46928bounde.EclipseManager", "4DF9E0F8.Netflix", "613EBCEA.PolarrPhotoEditorAcademicEdition", "6Wunderkinder.Wunderlist", "7EE7776C.LinkedInforWindows", "89006A2E.AutodeskSketchBook", "9E2F88E3.Twitter", "A278AB0D.DisneyMagicKingdoms", "A278AB0D.MarchofEmpires", "ActiproSoftwareLLC.562882FEEB491", "CAF9E577.Plex", "ClearChannelRadioDigital.iHeartRadio", "D52A8D61.FarmVille2CountryEscape", "D5EA27B7.Duolingo-LearnLanguagesforFree", "DB6EA5DB.CyberLinkMediaSuiteEssentials", "DolbyLaboratories.DolbyAccess", "Drawboard.DrawboardPDF", "Facebook.Facebook", "Fitbit.FitbitCoach", "Flipboard.Flipboard", "GAMELOFTSA.Asphalt8Airborne", "KeeperSecurityInc.Keeper", "Microsoft.3DBuilder", "Microsoft.549981C3F5F10", "Microsoft.549981C3F5F10", "Microsoft.Advertising.Xaml", "Microsoft.AppConnector", "Microsoft.BingFinance", "Microsoft.BingFoodAndDrink", "Microsoft.BingHealthAndFitness", "Microsoft.BingNews", "Microsoft.BingSports", "Microsoft.BingTranslator", "Microsoft.BingTravel", "Microsoft.BingWeather", "Microsoft.CommsPhone", "Microsoft.ConnectivityStore", "Microsoft.GamingServices", "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftPowerBIForWindows", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MinecraftUWP", "Microsoft.MixedReality.Portal", "Microsoft.NetworkSpeedTest", "Microsoft.News", "Microsoft.Office.Lens", "Microsoft.Office.OneNote", "Microsoft.Office.Sway", "Microsoft.OneConnect", "Microsoft.People", "Microsoft.Print3D", "Microsoft.ScreenSketch", "Microsoft.SkypeApp", "Microsoft.Wallet", "Microsoft.Whiteboard", "Microsoft.WindowsAlarms", "Microsoft.WindowsCamera", "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "Microsoft.WindowsPhone", "Microsoft.WindowsReadingList", "Microsoft.WindowsSoundRecorder", "Microsoft.Xbox.TCUI", "Microsoft.XboxApp", "Microsoft.XboxGameOverlay", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.YourPhone", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft3DViewer", "NORDCURRENT.COOKINGFEVER", "PandoraMediaInc.29680B314EFC2", "Playtika.CaesarsSlotsFreeCasino", "ShazamEntertainmentLtd.Shazam", "SlingTVLLC.SlingTV", "SpotifyAB.SpotifyMusic", "TheNewYorkTimes.NYTCrossword", "ThumbmunkeysLtd.PhototasticCollage", "TuneIn.TuneInRadio", "WinZipComputing.WinZipUniversal", "XINGAG.XING", "flaregamesGmbH.RoyalRevolt2", "king.com.*", "king.com.BubbleWitch3Saga", "king.com.CandyCrushSaga", "king.com.CandyCrushSodaSaga", "microsoft.windowscommunicationsapps"
        ForEach ($WindowsApp in $WindowsApps) {
            Get-AppxPackage -allusers $WindowsApp | Remove-AppxPackage -AllUsers
            Get-AppXProvisionedPackage -Online | Where-Object DisplayName -eq $WindowsApp | Remove-AppxProvisionedPackage -Online
        }
    
        #Prevents Apps from re-installing
        $cdm = @(
            "ContentDeliveryAllowed"
            "FeatureManagementEnabled"
            "OemPreInstalledAppsEnabled"
            "PreInstalledAppsEnabled"
            "PreInstalledAppsEverEnabled"
            "SilentInstalledAppsEnabled"
            "SubscribedContent-314559Enabled"
            "SubscribedContent-338387Enabled"
            "SubscribedContent-338388Enabled"
            "SubscribedContent-338389Enabled"
            "SubscribedContent-338393Enabled"
            "SubscribedContentEnabled"
            "SystemPaneSuggestionsEnabled"
        )
    
        New-Item -Force  "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        foreach ($key in $cdm) {
            Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
        }
    
        Mkdir -Force  "HKLM:\Software\Policies\Microsoft\WindowsStore"
        Set-ItemProperty "HKLM:\Software\Policies\Microsoft\WindowsStore" "AutoDownload" 2
    
        #Prevents "Suggested Applications" returning
        New-Item -Force  "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
        Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
    
    
        #  Description:
        #This script will remove and disable OneDrive integration.
    
        Import-Module -DisableNameChecking $PSScriptRoot\..\lib\Mkdir -Force .psm1
        Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1
    
        Write-Output "Kill OneDrive process"
        Stop-Process -Force -Name "OneDrive.exe"
        Stop-Process -Force -Name "explorer.exe"
    
        Write-Output "Remove OneDrive"
        if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
            & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
        }
        if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
            & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
        }
    
        Write-Output "Removing OneDrive leftovers"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
        #check if directory is empty before removing:
        If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
        }
    
        Write-Output "Disable OneDrive via Group Policies"
        Mkdir -Force  "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
        Set-ItemProperty "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1
    
        Write-Output "Remove Onedrive from explorer sidebar"
        New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
        mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        Set-ItemProperty "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
        mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        Set-ItemProperty "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
        Remove-PSDrive "HKCR"
    
        #Thank you Matthew Israelsson
        Write-Output "Removing run hook for new users"
        reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
        reg delete "HKEY_USERS\Default\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
        reg unload "hku\Default"
    
        Write-Output "Removing startmenu entry"
        Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
    
        Write-Output "Removing scheduled task"
        Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
    
        Write-Output "Restarting explorer"
        Start-Process "explorer.exe"
    
        Write-Output "Waiting for explorer to complete loading"
        Start-Sleep 10
    
        Write-Output "Removing additional OneDrive leftovers"
        foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
            Takeown-Folder $item.FullName
            Remove-Item -Recurse -Force $item.FullName
        }

        #Remove Bloatware Windows Apps
        Write-Output "Remove Reinstalled Apps"
        #Weather App
        Write-Output "removing Weather App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.BingWeather" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #Money App
        Write-Output "removing Money App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.BingFinance" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #Sports App
        Write-Output "removing Sports App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.BingSports" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #Twitter App
        Write-Output "removing Twitter App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*.Twitter" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #XBOX App
        #Write-Output "removing XBOX App"
        #Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.XboxApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
        #Sway App
        Write-Output "removing Sway App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.Office.Sway" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #Onenote App
        Write-Output "removing Onenote App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.Office.OneNote" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #Get Office App
        Write-Output "removing Get Office App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.MicrosoftOfficeHub" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #Get Skype App 
        Write-Output "removing skype App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.SkypeApp" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }

        #This includes fixes by xsisbest
        Start-Job -Name "FixWhitelistedApps" -ScriptBlock {
            
            If (!(Get-AppxPackage -AllUsers | Select-Object Microsoft.Paint3D, Microsoft.MSPaint, Microsoft.WindowsCalculator, Microsoft.WindowsStore, Microsoft.MicrosoftStickyNotes, Microsoft.WindowsSoundRecorder, Microsoft.Windows.Photos)) {
            
                #Credit to abulgatz for the 4 lines of code
                Get-AppxPackage -allusers Microsoft.Paint3D | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -allusers Microsoft.MSPaint | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -allusers Microsoft.WindowsCalculator | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -allusers Microsoft.WindowsStore | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -allusers Microsoft.MicrosoftStickyNotes | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -allusers Microsoft.WindowsSoundRecorder | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -allusers Microsoft.Windows.Photos | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } 
            }
        }

        Start-Job -Name "CheckDMWService" -ScriptBlock {
        
            If (Get-Service -Name dmwappushservice | Where-Object { $_.StartType -eq "Disabled" }) {
                Set-Service -Name dmwappushservice -StartupType Automatic
            }

            If (Get-Service -Name dmwappushservice | Where-Object { $_.Status -eq "Stopped" }) {
                Start-Service -Name dmwappushservice
            } 
        }

        Start-Job -Name "CheckInstallService" -ScriptBlock {
            If (Get-Service -Name InstallService | Where-Object { $_.Status -eq "Stopped" }) {  
                Start-Service -Name InstallService
                Set-Service -Name InstallService -StartupType Automatic 
            }
        }
    }

    #Debloating Scripts
    #This Start-Job -Name "finds any AppX/AppXProvisioned package and uninstalls it, except for Freshpaint, Windows Calculator, Windows Store, and Windows Photos.
    #Also, to note - This does NOT remove essential system services/software/etc such as .NET framework installations, Cortana, Edge, etc.

    #Creates a PSDrive to be able to access the 'HKCR' tree
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    Start-Job -Name "Start-Debloat" -ScriptBlock {
        
        #Removes AppxPackages
        #Credit to Reddit user /u/GavinEke for a modified version of my whitelist code
        [regex]$WhitelistedApps = 'Microsoft.ScreenSketch|Microsoft.Paint3D|Microsoft.WindowsCalculator|Microsoft.WindowsStore|Microsoft.Windows.Photos|CanonicalGroupLimited.UbuntuonWindows|`
        Microsoft.MicrosoftStickyNotes|Microsoft.MSPaint|Microsoft.WindowsCamera|.NET|Framework|Microsoft.HEIFImageExtension|Microsoft.ScreenSketch|Microsoft.StorePurchaseApp|`
        Microsoft.VP9VideoExtensions|Microsoft.WebMediaExtensions|Microsoft.WebpImageExtension|Microsoft.DesktopAppInstaller'
        Get-AppxPackage -AllUsers | Where-Object { $_.Name -NotMatch $WhitelistedApps } | Remove-AppxPackage -ErrorAction SilentlyContinue
        #Run this again to avoid error on 1803 or having to reboot.
        Get-AppxPackage -AllUsers | Where-Object { $_.Name -NotMatch $WhitelistedApps } | Remove-AppxPackage -ErrorAction SilentlyContinue
        $AppxRemoval = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -NotMatch $WhitelistedApps } 
        ForEach ( $App in $AppxRemoval) {
        
            Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName 
            
        }
    }

    Start-Job -Name "Remove-Keys" -ScriptBlock {  
        #These are the registry keys that it will delete.  
        $Keys = @(
            
            #Remove Background Tasks
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            #"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            #"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
            #Windows File
            "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            
            #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            #"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            #"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
            #Scheduled Tasks to delete
            "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            
            #Windows Protocol Keys
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            #"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            #"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
            #Windows Share Target
            "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        )
        
        #This writes the output of each key it is removing and also removes the keys listed above.
        ForEach ($Key in $Keys) {
            Write-Output "Removing $Key from registry"
            Remove-Item $Key -Recurse -ErrorAction SilentlyContinue
        }
    }
}
else {
    Write-Output "The Remove Bloatware Section Was Skipped..."
}

if ($disabletelemetry -eq $true) {
    Write-Host "Disabling Telemetry Reporting and Related Services" -ForegroundColor Green
    Start-Job -Name "Disable Telemetry" -ScriptBlock {
        #Disabling Telemetry and Services
        Write-Host "Disabling Telemetry and Related Services"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name CortanaConsent -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name CortanaConsent -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\" -Name "Search" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" -Type "String" -Value  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search and Cortana application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name "AU" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name AUOptions -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ScheduledInstallDay -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ScheduledInstallTime -Type "DWORD" -Value 3 -Force
        New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\" -Name "Update" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Update" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update\" -Name "ExcludeWUDriversInQualityUpdates" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdates" -Name Value -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name DisableOnline -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name BlockThirdPartyCookies -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name AutofillCreditCardEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name SyncDisabled -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Name AllowPrelaunch -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\" -Name "TabPreloader" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name AllowTabPreloading -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" -Name "MicrosoftEdge.exe" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" -Name Debugger -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name BackgroundModeEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft" -Name DoNotUpdateToEdgeWithChromium -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name AllowgameDVR -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\System\" -Name "GameConfigStore" -Force
        Set-ItemProperty -Path "HKLM:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\CurrentControlSet\" -Name "Control" -Force
        Set-ItemProperty -Path "HKLM:\Software\CurrentControlSet\Control" -Name SvcHostSplitThresholdInKB -Type "DWORD" -Value 04000000 -Force
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\" -Name "GameDVR" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\" -Name "GameDVR" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLm:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type "DWORD" -Value 0 -Force
    
        #Disable Razer Game Scanner Service
        Stop-Service "Razer Game Scanner Service"
        Set-Service  "Razer Game Scanner Service" -StartupType Disabled
    
        #Disable Windows Password Reveal Option
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name DisablePasswordReveal -Type "DWORD" -Value 1 -Force
    
        #Disable PowerShell 7+ Telemetry
        $POWERSHELL_Telemetry_OPTOUT = $true
        [System.Environment]::SetEnvironmentVariable('POWERSHELL_Telemetry_OPTOUT', 1 , [System.EnvironmentVariableTarget]::Machine)
        Write-Host $POWERSHELL_Telemetry_OPTOUT
    
        #Disable NET Core CLI Telemetry
        $DOTNET_CLI_Telemetry_OPTOUT = $true
        [System.Environment]::SetEnvironmentVariable('DOTNET_CLI_Telemetry_OPTOUT', 1 , [System.EnvironmentVariableTarget]::Machine)
        Write-Host $DOTNET_CLI_Telemetry_OPTOUT
    
        #Disable Office Telemetry
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Name "DisableTelemetry" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "VerboseLogging" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Name "VerboseLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" -Name "EnableCalendarLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" -Name "EnableCalendarLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Options" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Options" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Name "EnableLogging" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force
        #Disable Office Telemetry Agent
        schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE
        schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /DISABLE
        schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE
        schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /DISABLE
        #Disable Office Subscription Heartbeat
        schtasks /change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /DISABLE
        schtasks /change /TN "Microsoft\Office\Office 16 Subscription Heartbeat" /DISABLE
        #Disable Office feedback
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" -Name "Enabled" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" -Name "Enabled" -Type "DWORD" -Value 0 -Force
        #Disable Office Customer Experience Improvement Program
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" -Name "QMEnable" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" -Name "QMEnable" -Type "DWORD" -Value 0 -Force
    
        #Breaks Windows Account Logon - While not recommended many people still use it
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\wlidsvc" -Name Start -Type "DWORD" -Value 4 -Force
        #Set-Service wlidsvc -StartupType Disabled
    
        #Disable Visual Studio Code Telemetry
        New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Force
        New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Force
        New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Microsoft\VSCommon\14.0\SQM" -Force
        New-Item -Path "HKLM:\Software\Microsoft\VSCommon\15.0\SQM" -Force
        New-Item -Path "HKLM:\Software\Microsoft\VSCommon\16.0\SQM" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name TurnOffSwitch -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name DisableFeedbackDialog -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name DisableEmailInput -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name DisableScreenshotCapture -Type "DWORD" -Value 1 -Force
        Stop-Service "VSStandardCollectorService150"
        Set-Service  "VSStandardCollectorService150" -StartupType Disabled
    
        #Disable Unnecessary Windows Services
        Stop-Service "MessagingService"
        Set-Service "MessagingService" -StartupType Disabled
        Stop-Service "PimIndexMaintenanceSvc"
        Set-Service "PimIndexMaintenanceSvc" -StartupType Disabled
        Stop-Service "RetailDemo"
        Set-Service "RetailDemo" -StartupType Disabled
        Stop-Service "MapsBroker"
        Set-Service "MapsBroker" -StartupType Disabled
        Stop-Service "DoSvc"
        Set-Service "DoSvc" -StartupType Disabled
        Stop-Service "OneSyncSvc"
        Set-Service "OneSyncSvc" -StartupType Disabled
        Stop-Service "UnistoreSvc"
        Set-Service "UnistoreSvc" -StartupType Disabled
    
        ###Disable Windows Error Reporting ###
        ###The error reporting feature in Windows is what produces those alerts after certain program or operating system errors, prompting you to send the information about the problem to Microsoft.
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value 1 -Force
        Get-ScheduledTask -TaskName "QueueReporting" | Disable-ScheduledTask
    
        #Opt-out nVidia Telemetry
        Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name EnableRID44231 -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name EnableRID64640 -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name EnableRID66610 -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\NVIDIA Corporation\NvControlPanel2\Client" -Force
        Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\NvControlPanel2\Client" -Name OptInOrOutPreference -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" -Name Start -Type "DWORD" -Value 4 -Force
        Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\Startup\SendTelemetryData" -Name 0 -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" -Name "SendTelemetryData" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" -Name "Start" -Type "DWORD" -Value 4 -Force
        Stop-Service NvTelemetryContainer
        Set-Service NvTelemetryContainer -StartupType Disabled
        #Delete NVIDIA residual telemetry files
        Remove-Item -Recurse $env:systemdrive\System32\DriverStore\FileRepository\NvTelemetry*.dll
        Remove-Item -Recurse "$env:ProgramFiles\NVIDIA Corporation\NvTelemetry" | Out-Null
    
        #Disable Razer Game Scanner service
        Stop-Service "Razer Game Scanner Service"
        Set-Service "Razer Game Scanner Service" -StartupType Disabled
    
        #Disable Game Bar features
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name AllowgameDVR -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type "DWORD" -Value 0 -Force
    
        #Disable Logitech Gaming service
        Stop-Service "LogiRegistryService"
        Set-Service "LogiRegistryService" -StartupType Disabled
    
        #Disable Visual Studio Telemetry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\14.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\15.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\16.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name TurnOffSwitch -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableFeedbackDialog" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableEmailInput" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableScreenshotCapture" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name "TurnOffSwitch" -Type "DWORD" -Value 1 -Force
        Stop-Service "VSStandardCollectorService150"
        Set-Service "VSStandardCollectorService150" -StartupType Disabled
    
        #Block Google Chrome Software Reporter Tool
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type "String" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type "String" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type "String" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisallowRun" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -Name "1" -Type "String" -Value "software_reporter_tool.exe" /f
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name Debugger -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "Chrome
        Enabled" -Type "String" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type "String" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type "String" -Value 0 -Force
    
        #Disable storing sensitive data in Acrobat Reader DC
        Set-ItemProperty -Path "HKCU:\Software\Adobe\Adobe ARM\1.0\ARM" -Name "iCheck" -Type "String" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "cSharePoint" -Type "String" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeDocumentServices" -Type "String" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeSign" -Type "String" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bTogglePrefSync" -Type "String" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleWebConnectors" -Type "String" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bAdobeSendPluginToggle" -Type "String" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bUpdater" -Type "String" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Adobe\Adobe ARM\1.0\ARM" -Name "iCheck" -Type "String" -Value 0 -Force
    
        #Disable Adobe Acrobat Update Service
        Set-Service "Adobe Acrobat Update Task" -StartupType Disabled
        Set-Service "Adobe Flash Player Updater" -StartupType Disabled
        Set-Service "adobeflashplayerupdatesvc" -StartupType Disabled
        Set-Service "adobeupdateservice" -StartupType Disabled
        Set-Service "AdobeARMservice" -StartupType Disabled
    
        #Disable CCleaner Health Check
        Stop-Process -Force -Name  ccleaner.exe
        Stop-Process -Force -Name  ccleaner64.exe
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HomeScreen" -Type "String" -Value 2 -Force
    
        #Disable CCleaner Monitoring && more
        Stop-Process -Force -Name "IMAGENAME eq CCleaner*"
        schtasks /Change /TN "CCleaner Update" /Disable
        Get-ScheduledTask -TaskName "CCleaner Update" | Disable-ScheduledTask
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "Monitoring" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HelpImproveCCleaner" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "SystemMonitoring" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateAuto" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateCheck" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "CheckTrialOffer" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)HealthCheck" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)QuickClean" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)QuickCleanIpm" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)GetIpmForTrial" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdater" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdaterIpm" -Type "DWORD" -Value 0 -Force
    
        #Disable Dropbox Update service
        Set-Service dbupdate -StartupType Disabled
        Set-Service dbupdatem -StartupType Disabled
        Get-ScheduledTask -TaskName "DropboxUpdateTaskMachineCore" | Disable-ScheduledTask
        Get-ScheduledTask -TaskName "DropboxUpdateTaskMachineUA" | Disable-ScheduledTask
        #schtasks /Change /TN "DropboxUpdateTaskMachineCore" /Disable
        #schtasks /Change /TN "DropboxUpdateTaskMachineUA" /Disable
    
        #Disable Google update service
        Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" | Disable-ScheduledTask
        Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineUA" | Disable-ScheduledTask
        #schtasks /Change /TN "GoogleUpdateTaskMachineCore" /Disable
        #schtasks /Change /TN "GoogleUpdateTaskMachineUA" /Disable
    
        #Disable Media Player Telemetry
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type "DWORD" -Value 1 -Force
        Set-Service WMPNetworkSvc -StartupType Disabled
    
        #Disable Microsoft Office Telemetry
        Get-ScheduledTask -TaskName "OfficeTelemetryAgentFallBack2016" | Disable-ScheduledTask
        Get-ScheduledTask -TaskName "OfficeTelemetryAgentLogOn2016" | Disable-ScheduledTask
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\osm" -Name "Enablelogging" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\osm" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force
    
        #Disable Mozilla Firefox Telemetry
        Set-ItemProperty -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableTelemetry" -Type "DWORD" -Value 1 -Force
        #Disable default browser agent reporting policy
        Set-ItemProperty -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableDefaultBrowserAgent" -Type "DWORD" -Value 1 -Force
        #Disable default browser agent reporting services
        schtasks.exe /change /disable /tn "\Mozilla\Firefox Default Browser Agent 308046B0AF4A39CB"
        schtasks.exe /change /disable /tn "\Mozilla\Firefox Default Browser Agent D2CEEC440E2074BD"
    }
}
else {
    Write-Output "The Disable Telemetry Section Was Skipped..."
}

if ($privacy -eq $true) {
    Write-Host "Enabling Privacy and Security Focused" -ForegroundColor Green
    Start-Job -Name "Enable Privacy and Security Settings" -ScriptBlock {
        #Do not let apps on other devices open and message apps on this device, and vice versa
        New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name RomeSdkChannelUserAuthzPolicy -PropertyType DWord -Value 1 -Force
        #Turn off Windows Location Provider
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type "DWORD" -Value "1" -Force
        #Turn off location scripting
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type "DWORD" -Value "1" -Force
        #Turn off location
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value "1" -Type "DWORD" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value "0" -Type "DWORD" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "Value" -Type "String" -Value "Deny" -Force
        #Deny app access to location
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value "0" -Type "DWORD" -Force
        #Deny app access to motion data
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Value "Deny" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMotion" -Type "DWORD" -Value 2 -Force
        #Deny app access to phone
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Type "DWORD" -Value 2 -Force
        #Deny app access to trusted devices
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTrustedDevices" -Type "DWORD" -Value 2 -Force
        #Deny app sync with devices (unpaired, beacons, TVs etc.)
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type "DWORD" -Value 2 -Force
        #Deny app access to diagnostics info about your other apps
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" -Type "String" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Type "DWORD" -Value 2 -Force
        #Deny app access to your contacts
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Type "DWORD" -Value 2 -Force
        #Deny app access to Notifications
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Type "DWORD" -Value 2 -Force
        #Deny app access to Calendar
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Type "DWORD" -Value 2 -Force
        #Deny app access to call history
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Type "DWORD" -Value 2 -Force
        #Deny app access to email
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Type "DWORD" -Value 2 -Force
        #Deny app access to tasks
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name "Value" -Value "Deny" -Type "String" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Type "DWORD" -Value 2 -Force
        #Deny app access to messaging (SMS / MMS)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -Type "String" -Name "Value" -Value "DENY" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Type "DWORD" -Value 2 -Force
        #Deny app access to radios
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Type "DWORD" -Value 2 -Force
        #Deny app access to bluetooth devices
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name "Value" -Value "Deny" -Type "String" -Force
        #Disable device metadata retrieval (breaks auto updates)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type "DWORD" -Value 1 -Force
        #Do not include drivers with Windows Updates
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type "DWORD" -Value 1 -Force
        #Prevent Windows Update for device driver search
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type "DWORD" -Value 0 -Force
        #Disable Customer Experience Improvement (CEIP/SQM)
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type "DWORD" -Value "0" -Force
        #Disable Application Impact Telemetry (AIT)
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type "DWORD" -Value "0" -Force
        #Disable diagnostics telemetry
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 4 -Force 
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushsvc" -Name "Start" -Type "DWORD" -Value 4 -Force 
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 4 -Force 
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type "DWORD" -Value 4 -Force
        Stop-Service "DiagTrack"
        Set-Service "DiagTrack" -StartupType Disabled
        Stop-Service "dmwappushservice"
        Set-Service "dmwappushservice" -StartupType Disabled
        Stop-Service "diagnosticshub.standardcollector.service"
        Set-Service "diagnosticshub.standardcollector.service" -StartupType Disabled
        Stop-Service "diagsvc"
        Set-Service "diagsvc" -StartupType Disabled
        #Disable Customer Experience Improvement Program
        schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
        schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
        schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE
        #Disable Webcam Telemetry (devicecensus.exe)
        schtasks /change /TN "Microsoft\Windows\Device Information\Device" /DISABLE
        # Disable Application Experience (Compatibility Telemetry)
        schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
        schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE
        schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE
        schtasks /change /TN "Microsoft\Windows\Application Experience\AitAgent" /DISABLE
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
        #Disable telemetry in data collection policy
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWORD" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force 
        #Disable license telemetry
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type "DWORD" -Value "1" -Force
        #Disable error reporting
        #Disable Windows Error Reporting (WER)
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value "1" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value "1" -Force
        #DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultConsent" -Type "DWORD" -Value "0" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultOverrideBehavior" -Type "DWORD" -Value "1" -Force
        #Disable WER sending second-level data
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Type "DWORD" -Value "1" -Force
        #Disable WER crash dialogs, popups
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Type "DWORD" -Value "1" -Force
        schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
        schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
        #Disable Windows Error Reporting Service
        Stop-Service "WerSvc" 
        Set-Service "WerSvc" -StartupType Disabled
        Stop-Service "wercplsupport" 
        Set-Service "wercplsupport" -StartupType Disabled
        #Disable all settings sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSyncOnPaidNetwork" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" -Name "SyncPolicy" -Type "DWORD" -Value 5 -Force
        #Disable Application Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable App Sync Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable App Sync Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable Desktop Theme Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable Personalization Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable Start Layout Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable Web Browser Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWebBrowserSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWebBrowserSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable Windows Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable Windows Insider Service
        Stop-Service "wisvc" 
        Set-Service "wisvc" -StartupType Disabled
        #Do not let Microsoft try features on this build
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -Name "value" -Type "DWORD" -Value 0 -Force
        #Disable getting preview builds of Windows
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Type "DWORD" -Value 0 -Force
        #Remove "Windows Insider Program" from Settings
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "HideInsiderPage" -Type "DWORD" -Value "1" -Force
        #Disable ad customization with Advertising ID
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type "DWORD" -Value 1 -Force
        #Disable targeted tips
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Type "DWORD" -Value "1" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type "DWORD" -Value "1" -Force
        #Turn Off Suggested Content in Settings app
        New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -PropertyType "DWord" -Value "0" -Force
        New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -PropertyType "DWord" -Value "0" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value "0" -Type "DWORD" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value "0" -Type "DWORD" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value "0" -Type "DWORD" -Force
        #Disable cortana
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "value" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CanCortanaBeEnabled" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent"  -Value 0 -Type "DWORD" -Force 
        #Disable web search in search bar
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name DisableWebSearch -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type "DWORD" -Force                   
        #Disable search web when searching pc
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name ConnectedSearchUseWeb -Type "DWORD" -Value 0 -Force
        #Disable search indexing encrypted items / stores
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowIndexingEncryptedStoresOrItems -Type "DWORD" -Value 0 -Force
        #Disable location based info in searches
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowSearchToUseLocation -Type "DWORD" -Value 0 -Force
        #Disable language detection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AlwaysUseAutoLangDetection -Type "DWORD" -Value 0 -Force
        #Opt out from Windows privacy consent
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type "DWORD" -Value 0 -Force
        #Disable cloud speech recognation
        New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type "DWORD" -Value 0 -Force
        #Disable text and handwriting collection
        New-Item -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Force
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\TabletPC" -Force
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type "DWORD" -Value 0 -Force
        #Disable Windows feedback
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type "DWORD" -Value 0 -Force 
        reg delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type "DWORD" -Value 1 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type "DWORD" -Value 1 -Force
        #Disable Wi-Fi sense
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type "DWORD" -Value 0 -Force 
        #Disable App Launch Tracking
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Type "DWORD" -Force
        #Disable Activity Feed
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value "0" -Type "DWORD" -Force
        #Disable feedback on write (sending typing info)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Type "DWORD" -Value 0 -Force
        #Disable Windows DRM internet access
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type "DWORD" -Value 1 -Force
        #Disable game screen recording
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type "DWORD" -Value 0 -Force
        #Disable Auto Downloading Maps
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AllowUntriggeredNetworkTrafficOnSettingsPage" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Type "DWORD" -Value 0 -Force
        #Disable Website Access of Language List
        Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type "DWORD" -Value 1 -Force
        #Disable Inventory Collector
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type "DWORD" -Value 1 -Force
        #Do not send Watson events
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericReports" -Type "DWORD" -Value 1 -Force
        #Disable Malicious Software Reporting tool diagnostic data
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type "DWORD" -Value 1 -Force
        #Disable local setting override for reporting to Microsoft MAPS
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Type "DWORD" -Value 0 -Force
        #Turn off Windows Defender SpyNet reporting
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type "DWORD" -Value 0 -Force
        #Do not send file samples for further analysis
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type "DWORD" -Value 2 -Force
        #Disable live tile data collection
        New-Item -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Name "PreventLiveTileDataCollection" -Type "DWORD" -Value 1 -Force
        #Disable MFU tracking
        New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableMFUTracking" -Type "DWORD" -Value 1 -Force
        #Disable recent apps
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableRecentApps" -Type "DWORD" -Value 1 -Force
        #Turn off backtracking
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "TurnOffBackstack" -Type "DWORD" -Value 1 -Force
        #Disable Search Suggestions in Edge
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -Name "ShowSearchSuggestionsGlobal" -Type "DWORD" -Value 0 -Force
        #Disable Geolocation in Internet Explorer
        New-Item -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Geolocation" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Geolocation" -Name "PolicyDisableGeolocation" -Type "DWORD" -Value 1 -Force
        #Disable Internet Explorer InPrivate logging
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -Name "DisableLogging" -Type "DWORD" -Value 1 -Force
        #Disable Internet Explorer CEIP
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Name "DisableCustomerImprovementProgram" -Type "DWORD" -Value 0 -Force
        #Disable calling legacy WCM policies
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "CallLegacyWCMPolicies" -Type "DWORD" -Value 0 -Force
        #Do not send Windows Media Player statistics
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Type "DWORD" -Value 0 -Force
        #Disable metadata retrieval
        New-Item -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer"  -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type "DWORD" -Value 1 -Force
        #Disable dows Media Player Network Sharing Service
        Stop-Service "WMPNetworkSvc" 
        Set-Service "WMPNetworkSvc" -StartupType Disabled
        #Disable lock screen camera
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Type "DWORD" -Value 1 -Force
        #Disable remote Assistance
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Type "DWORD" -Value 0 -Force
        #Disable AutoPlay and AutoRun
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type "DWORD" -Value 255 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Type "DWORD" -Value 1 -Force
        #Disable Windows Installer Always install with elevated privileges
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Type "DWORD" -Value 0 -Force
        #Refuse less secure authentication
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Type "DWORD" -Value 5 -Force
        #Disable the Windows Connect Now wizard
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableFlashConfigRegistrar" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableInBand802DOT11Registrar" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableUPnPRegistrar" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableWPDRegistrar" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -Type "DWORD" -Value 0 -Force
        #Disable online tips
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Type "DWORD" -Value 0 -Force
        #Turn off Internet File Association service
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInternetOpenWith" -Type "DWORD" -Value 1 -Force
        #Turn off the "Order Prints" picture task
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoOnlinePrintsWizard" -Type "DWORD" -Value 1 -Force
        #Disable the file and folder Publish to Web option
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPublishingWizard" -Type "DWORD" -Value 1 -Force
        #Prevent downloading a list of providers for wizards
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Type "DWORD" -Value 1 -Force
        #Do not keep history of recently opened documents
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type "DWORD" -Value 1 -Force
        #Clear history of recently opened documents on exit
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Type "DWORD" -Value 1 -Force
        #Disable lock screen app notifications
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Type "DWORD" -Value 1 -Force
        #Disable Live Tiles push notifications
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Type "DWORD" -Value 1 -Force
        #Turn off "Look For An App In The Store" option
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type "DWORD" -Value 1 -Force
        #Do not show recently used files in Quick Access
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -Type "DWORD" -Force
        reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f
        #Disable Sync Provider Notifications
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type "DWORD" -Force
        #Enable camera on/off OSD notifications
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\OEM\Device\Capture" -Name "NoPhysicalCameraLED" -Value 1 -Type "DWORD" -Force
    
        #Windows Defender Privacy Options
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type "DWORD" -Value 1 -Force
        #Remove the automatic start item for OneDrive from the default user profile registry hive
        Write-Output "remove onedrive automatic start"
        Remove-Item -Path "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\OneDrive.lnk" -Force 
        Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Load HKLM\\Temp C:\\Users\\Default\\NTUSER.DAT" -Wait
        Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Delete HKLM\\Temp\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name OneDriveSetup -Force" -Wait
        Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Unload HKLM\\Temp"
        #Disable Cortana
        Write-Output "disabling cortona"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name AllowSearchToUseLocation -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name DisableWebSearch -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name ConnectedSearchUseWeb -Type "DWORD" -Value 0 -Force
        #Disable Device Metadata Retrieval
        Write-Output "Disable Device Metadata Retrieval"
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\" -Name "Device Metadata" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Device Metadata" -Name PreventDeviceMetadataFromNetwork -Type "DWORD" -Value 1 -Force
        #Disable Find My Device
        Write-Output "Disable Find My Device"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FindMyDevice" -Name AllowFindMyDevice -Type "DWORD" -Value 0 -Force
        #Disable Font Streaming
        Write-Output "Disable Font Streaming"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableFontProviders -Type "DWORD" -Value 0 -Force
        #Disable Insider Preview Builds
        Write-Output "Disable Insider Preview Builds"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds" -Name AllowBuildPreview -Type "DWORD" -Value 0 -Force
        Write-Output "IE Optimizations"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name EnabledV9 -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "Geolocation" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Geolocation" -Name PolicyDisableGeolocation -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Explorer\" -Name "AutoComplete" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -Name AutoSuggest -Type "String" -Value no -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer" -Name AllowServicePoweredQSA -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "Suggested Sites" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Suggested Sites" -Name Enabled -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "FlipAhead" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\FlipAhead" -Name Enabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Name BackgroundSyncStatus -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name AllowOnlineTips -Type "DWORD" -Value 0 -Force
        #Restrict License Manager
        #Write-Output "Restrict License Manager"
        #Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LicenseManager" -Name Start -Type "DWORD" -Value 4 -Force
        #Disable Live Tiles
        Write-Output "Disable Live Tiles"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoCloudApplicationNotification -Type "DWORD" -Value 1 -Force
        #Disable Windows Mail App
        Write-Output "Disable Windows Mail App"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Mail" -Name ManualLaunchAllowed -Type "DWORD" -Value 0 -Force
        #Disable Network Connection Status Indicator
        #Write-Output "Disable Network Connection Status Indicator"
        #Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name NoActiveProbe -Type "DWORD" -Value 1 -Force
        #Disable Offline Maps
        Write-Output "Disable Offline Maps"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Maps" -Name AutoDownloadAndUpdateMapData -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Maps" -Name AllowUntriggeredNetworkTrafficOnSettingsPage -Type "DWORD" -Value 0 -Force
    
        ##General VM Optimizations
        #Change TTL for ISP throttling workaround
        int ipv4 set glob defaultcurhoplimit=65
        int ipv6 set glob defaultcurhoplimit=65
        #Auto Cert Update
        Write-Output "Auto Cert Update"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot" -Name DisableRootAutoUpdate -Type "DWORD" -Value 0 -Force
        #Turn off Let websites provide locally relevant content by accessing my language list
        Write-Output "Turn off Let websites provide locally relevant content by accessing my language list"
        Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Type "DWORD" -Value 1 -Force
        #Turn off Let Windows track app launches to improve Start and search results
        Write-Output "Turn off Let Windows track app launches to improve Start and search results"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Start_TrackProgs -Type "DWORD" -Value 0 -Force
        #Turn off Let apps use my advertising ID for experiences across apps (turning this off will reset your ID
        Write-Output "Turn off Let apps use my advertising ID for experiences across apps (turning this off will reset your ID"
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\" -Name "AdvertisingInfo"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo" -Name DisabledByGroupPolicy -Type "DWORD" -Value 1 -Force
        #Turn off Let websites provide locally relevant content by accessing my language list
        Write-Output "Turn off Let websites provide locally relevant content by accessing my language list"
        Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Type "DWORD" -Value 1 -Force
        #Turn off Let apps on my other devices open apps and continue experiences on this device
        Write-Output "Turn off Let apps on my other devices open apps and continue experiences on this device"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableCdp -Type "DWORD" -Value 1 -Force
        #Turn off Location for this device
        Write-Output "Turn off Location for this device"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsAccessLocation -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name DisableLocation -Type "DWORD" -Value 1 -Force
        #Turn off Windows should ask for my feedback
        Write-Output "Turn off Windows should ask for my feedback"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name DoNotShowFeedbackNotifications -Type "DWORD" -Value 1 -Force
        #Turn Off Send your device data to Microsoft
        Write-Output "Turn Off Send your device data to Microsoft"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Type "DWORD" -Value 0 -Force
        #Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data
        Write-Output "Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableTailoredExperiencesWithDiagnosticData -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\" -Name "CloudContent" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableTailoredExperiencesWithDiagnosticData -Type "DWORD" -Value 1 -Force
        #Turn off Let apps run in the background
        Write-Output "Turn off Let apps run in the background"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsRunInBackground -Type "DWORD" -Value 2 -Force
        #Software Protection Platform
        #Opt out of sending KMS client activation data to Microsoft
        Write-Output "Opt out of sending KMS client activation data to Microsoft"
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\" -Name "Software Protection Platform" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name NoGenTicket -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name NoAcquireGT -Type "DWORD" -Value 1 -Force
        #Turn off Messaging cloud sync
        Write-Output "Turn off Messaging cloud sync"
        New-Item -Path "HKCU:\Software\Microsoft\" -Name "Messaging" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Messaging" -Name CloudServiceSyncEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Messaging" -Name CloudServiceSyncEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name DisableSettingSync -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name DisableSettingSyncUserOverride -Type "DWORD" -Value 1 -Force
        #Disable Teredo
        #Broke too many things. Should be disabled in an enterprise, but not for personal systems
        #Write-Output "Disable Teredo"
        #Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name Teredo_State -Type "String" -Value Disabled -Force
        #Delivery Optimization
        Write-Output "Delivery Optimization"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name DODownloadMode -Type "DWORD" -Value 99 -Force
        ###Disable app access to account info
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to calendar
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to call history
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to contacts
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to diagnostic information
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to documents
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to email
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to file system
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to location
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to messaging
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to motion
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to notifications
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Type "String" -Name Value -Value "DENY" -Force
        ###Disable app access to other devices
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" -Name Value -Type "String" -Value "DENY" -Force
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to call
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to pictures
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to radios
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to tasks
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to videos
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable tracking of app starts ###
        ###Windows can personalize your Start menu based on the apps that you launch. ###
        ###This allows you to quickly have access to your list of Most used apps both in the Start menu and when you search your device.
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Start_TrackProgs -Type "DWORD" -Value 0 -Force
        ###Disable Bing in Windows Search ###
        ###Like Google, Bing is a search engine that needs your data to improve its search results. Windows 10, by default, sends everything you search for in the Start Menu to their servers to give you results from Bing search. ###
        ###These searches are then uploaded to Microsoft's Privacy Dashboard.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "BingSearchEnabled" -Type "DWORD" -Value 0 -Force
        ###Disable Cortana ###
        ###With the Anniversary Update, Microsoft hid the option to disable Cortana. This policy makes it possible again. It will block the outbound network connections completely in the Firewall.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type "DWORD" -Value 0 -Force
        If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules")) {
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" -Type "String" -Value "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search and Cortana application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" -Force
    
        #Display full path in explorer
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\" -Name "CabinetState" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name FullPath -Type "DWORD" -Value 1 -Force
    
        #Make icons easier to touch in explorer
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name FileExplorerInTouchImprovement -Type "DWORD" -Value 1 -Force
    
        Write-Output "Disabling Telemetry via Group Policies"
        New-Item -Force  "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
        Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 
     
        ###Prevent Edge from running in background ###
        ###On the new Chromium version of Microsoft Edge, extensions and other services can keep the browser running in the background even after it's closed. ###
        ###Although this may not be an issue for most desktop PCs, it could be a problem for laptops and low-end devices as these background processes can increase battery consumption and memory usage. The background process displays an icon in the system tray and can always be closed from there. ###
        ###If you run enable this policy the background mode will be disabled.
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Type "DWORD" -Value 0 -Force
    
        ###Disable synchronization of data ###
        ###This policy will disable synchronization of data using Microsoft sync services.
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SyncDisabled" -Type "DWORD" -Value 1 -Force
    
        ###Disable AutoFill for credit cards ###
        ###Microsoft Edge's AutoFill feature lets users auto complete credit card information in web forms using previously stored information. ###
        ###If you enable this policy, Autofill never suggests or fills credit card information, nor will it save additional credit card information that users might submit while browsing the web.
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AutofillCreditCardEnabled" -Type "DWORD" -Value 0 -Force
    
        ###Disable Game Bar features ###
        ###The Game DVR is a feature of the Xbox app that lets you use the Game bar (Win+G) to record and share game clips and screenshots in Windows 10. However, you can also use the Game bar to record videos and take screenshots of any app in Windows 10. ###
        ###This Policy will disable the Windows Game Recording and Broadcasting.
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type "DWORD" -Value 0 -Force
        ###Block suggestions and automatic Installation of apps ###
        ###Microsoft flushes various apps into the system without being asked, especially games such as Candy Crush Saga. Users have to uninstall these manually if they don't want them on their computer. ###
        ###To prevent these downloads from starting in the first place, a small intervention in the registry helps. Suggested apps pinned to Start are basically just advertising. This script will also disable suggested apps (ex: Candy Crush Soda Saga) for all accounts.
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type "DWORD" -Value 0 -Force
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type "DWORD" -Value 1 -Force
    
        ###Disable Clipboard history ###
        ###With Windows 10 build 17666 or later, Microsoft has allowed cloud synchronization of clipboard. It is a special feature to sync clipboard content across all your devices connected with your Microsoft Account.
        New-Item -Path "HKCU:\Software\Microsoft\" -Name "Clipboard" -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type "DWORD" -Value 0 -Force
        ###Disable Compatibility Telemetry ###
        ###The Windows Compatibility Telemetry process is periodically collecting a variety of technical data about your computer and its performance and sending it to Microsoft for its Windows Customer Experience Improvement Program. It is enabled by default, and the data points are useful for Microsoft to improve Windows 10. ###
        ###The CompatTelRunner.exe file is also used to upgrade your system to the latest OS version and install the latest updates. ###
        ###The process is not generally required for the Windows operating system to run properly and can be stopped or deleted. This script will disable the CompatTelRunner.exe (Compatibility Telemetry process) in a more cleaner way using Image File Execution Options Debugger Value. Setting this value to an executable designed to kill processes disables it. Windows won't re-enable it with almost each update. 
        If (!(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe")) {
            New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
    
     
        ###Disable Customer Experience Improvement Program ###
        Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask
        ###Disable Location tracking ###
        ###When Location Tracking is turned on, Windows and its apps are allowed to detect the current location of your computer or device. ###
        ###This can be used to pinpoint your exact location, e.g. Map traces the location of PC and helps you in exploring nearby restaurants.
        If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
            New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type "String" -Value "Deny" -Force
        ###Disable Telemetry in Windows 10 ###
        ###As you use Windows 10, Microsoft will collect usage information. All its options are available in Settings -> Privacy - Feedback and Diagnostics. There you can set the options "Diagnostic and usage data" to Basic, Enhanced and Full. This will set diagnostic data to Basic, which is the lowest level available for all consumer versions of Windows 10 ###
        ###NOTE: Diagnostic Data must be set to Full to get preview builds from Windows-Insider-Program! Just set the value of the AllowTelemetry key to "3" to revert the policy changes. All other changes remain unaffected.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\" -Name "DataCollection" -Type "DWORD" -Value 0 -Force
        #Stop and Disable Diagnostic Tracking Service
        New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 4 -Force
        Stop-Service -Name DiagTrack
        Set-Service -Name DiagTrack -StartupType Disabled
        #Stop and Disable dmwappushservice Service
        New-Item -Path "HKLM:\SYSTEM\ControlSet001\Services\" -Name "dmwappushsvc" -Force
        New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushsvc" -Name "Start" -Type "DWORD" -Value 4 -Force
        Stop-Service -Name dmwappushservice
        Set-Service -Name dmwappushservice -StartupType Disabled
        ###Disable Timeline history ###
        ###Microsoft made Timeline available to the public with Windows 10 build 17063. It collects a history of activities you've performed, including files you've opened and web pages you've viewed in Edge.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type "DWORD" -Value 0 -Force
        ###Disable Windows Tips ###
        ###Microsoft uses diagnostic information to determine which tips are appropriate. If you enable this policy, you will no longer see Windows Tips, e.g. Spotlight and Consumer Features, Feedback Notifications etc.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Type "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeature" -Type "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type "DWORD" -Value 1 -Force
    
        ###Do not show feedback notifications ###
        ###Windows 10 doesn’t just automatically collect information about your computer usage. It does do that, but it may also pop up from time to time and ask for feedback. This information is used to improve Windows 10 - in theory. As of Windows 10’s “November Update,” the Windows Feedback application is installed by default on all Windows 10 PCs. ###
        ###If you are running Windows 10 in a corporate setting, you should likely disable the Windows Feedback prompts that appear every few weeks.
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type "DWORD" -Value 0 -Force
        ###Prevent using diagnostic data ###
        ###Starting with Windows 10 build 15019, a new privacy setting to "let Microsoft provide more tailored experiences with relevant tips and recommendations by using your diagnostic data" has been added. By enabling this policy you can prevent Microsoft from using your diagnostic data. 
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type "DWORD" -Value 0 -Force
        ###Turn off Advertising ID for Relevant Ads ###
        ###Windows 10 comes integrated with advertising. Microsoft assigns a unique identificator to track your activity in the Microsoft Store and on UWP apps to target you with relevant ads. ###
        ###If someone is giving you personalized ads, it means they are tracking your data. Turn off the advertising feature from Windows 10 with this policy to stay secure.
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type "DWORD" -Value 0 -Force
        ###Turn off help Microsoft improve typing and writing ###
        ###When the Getting to know you privacy setting is turned on for inking & typing personalization in Windows 10, you can use your typing history and handwriting patterns to create a local user dictionary for you that is used to make better typing suggestions and improve handwriting recognition for each of the languages you use.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type "DWORD" -Value 1 -Force
        ###Disable password reveal button ###
        ###On the new login screen, Microsoft added a password review button that displays what's in the password box in plain text when pressed. Note that, disabling Password Reveal button disables this feature not only in login screen but also in Microsoft Edge, Internet Explorer as well. ###
        ###Visible passwords may be seen by nearby persons, compromising them. The password reveal button can be used to display an entered password and should be disabled with this policy.
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Type "DWORD" -Value 1 -Force
    
        ###Disable Windows Media DRM Internet Access ###
        ###DRM stands for digital rights management. DRM is a technology used by content providers, such as online stores, to control how the digital music and video files you obtain from them are used and distributed. Online stores sell and rent songs and movies that have DRM applied to them. ###
        ###If the Windows Media Digital Rights Management should not get access to the Internet, you can enable this policy to prevent it.
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\WMDRM")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type "DWORD" -Value 1 -Force
    
        ###Disable forced updates ###
        ###This will notify when updates are available, and you decide when to install them.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type "DWORD" -Value 2 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Type "DWORD" -Value 3 -Force
    
        ###Turn off distributing updates to other computers ###
        ###Windows 10 lets you download updates from several sources to speed up the process of updating the operating system. ###
        ###If you don't want your files to be shared by others and exposing your IP address to random computers, you can apply this policy and turn this feature off. ###
        ###Acceptable selections include:
        ###Bypass (100) 
        ###Group (2)
        ###HTTP only (0) Enabled by SharpApp!
        ###LAN (1)
        ###Simple (99)
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type "DWORD" -Value 0 -Force
    
    
        Write-Output "Defuse Windows search settings"
        Set-WindowsSearchSetting -EnableWebResultsSetting $false
    
        Write-Output "Set general privacy options"
        #"Let websites provide locally relevant content by accessing my language list"
        Set-ItemProperty "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1
        #Locaton aware printing (changes default based on connected network)
        Mkdir "HKCU:\Printers\Defaults" -Force
        New-Item -Path "HKCU:\Printers\" -Name "Defaults" -Force
        Set-ItemProperty "HKCU:\Printers\Defaults" "NetID" "{00000000-0000-0000-0000-000000000000}"
        #"Send Microsoft info about how I write to help us improve typing and writing in the future"
        Mkdir "HKCU:\Software\Microsoft\Input\TIPC" -Force
        Set-ItemProperty "HKCU:\Software\Microsoft\Input\TIPC" "Enabled" 0
        #"Let apps use my advertising ID for experiencess across apps"
        Mkdir -Force  "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
        #"Turn on SmartScreen Filter to check web content"
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0
    
        Write-Output "Disable synchronisation of settings"
        #These only apply if you log on using Microsoft account
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync" "BackupPolicy" 0x3c
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync" "DeviceMetadataUploaded" 0
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync" "PriorLogons" 1
        $groups = @(
            "Accessibility"
            "AppSync"
            "BrowserSettings"
            "Credentials"
            "DesktopTheme"
            "Language"
            "PackageState"
            "Personalization"
            "StartLayout"
            "Windows"
        )
        foreach ($group in $groups) {
            Mkdir -Force  "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group"
            Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group" "Enabled" 0
        }
    
        Write-Output "Set privacy policy accepted state to 0"
        #Prevents sending speech, inking and typing samples to MS (so Cortana
        #can learn to recognise you)
        Mkdir -Force  "HKCU:\Software\Microsoft\Personalization\Settings"
        Set-ItemProperty "HKCU:\Software\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0
    
        Write-Output "Do not scan contact informations"
        #Prevents sending contacts to MS (so Cortana can compare speech etc samples)
        Mkdir -Force  "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"
        Set-ItemProperty "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0
    
        Write-Output "Inking and typing settings"
        #Handwriting recognition personalization
        Mkdir -Force  "HKCU:\Software\Microsoft\InputPersonalization"
        Set-ItemProperty "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
        Set-ItemProperty "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
    
        Write-Output "Microsoft Edge settings"
        Mkdir -Force  "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main"
        Set-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" "DoNotTrack" 1
        Mkdir -Force  "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes"
        Set-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" "ShowSearchSuggestionsGlobal" 0
        Mkdir -Force  "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead"
        Set-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" "FPEnabled" 0
        Mkdir -Force  "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
        Set-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" "EnabledV9" 0
    
        Write-Output "Disable background access of default apps"
        foreach ($key in (Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
            Set-ItemProperty ("HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + $key.PSChildName) "Disabled" 1
        }
    
        Write-Output "Denying device access"
        #Disable sharing information with unpaired devices
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Type" "LooselyCoupled"
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Value" "Deny"
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "InitialAppValue" "Unspecified"
    
        Write-Output "Disable location sensor"
        Mkdir -Force  "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0
    
        Write-Output "Disable submission of Windows Defender findings (w/ elevated privileges)"
        Takeown-Registry("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender\Spynet")
        Set-ItemProperty "HKLM:\Software\Microsoft\Windows Defender\Spynet" "SpyNetReporting" 0       #write-protected even after takeown ?!
        Set-ItemProperty "HKLM:\Software\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent" 0
    
        Write-Output "Do not share wifi networks"
        $user = New-Object System.Security.Principal.NTAccount($env:UserName)
        $sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).value
        Mkdir -Force  ("HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid)
        Set-ItemProperty ("HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid) "FeatureStates" 0x33c
        Set-ItemProperty "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseCredShared" 0
        Set-ItemProperty "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseOpen" 0
        
        #Creates a PSDrive to be able to access the 'HKCR' tree
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
            
        #Disables Windows Feedback Experience
        Write-Output "Disabling Windows Feedback Experience program"
        $Advertising = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
        If (Test-Path $Advertising) {
            Set-ItemProperty $Advertising -Name Enabled -Value 0 -Verbose
        }
            
        #Stops Cortana from being used as part of your Windows Search Function
        Write-Output "Stopping Cortana from being used as part of your Windows Search Function"
        $Search = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
        If (Test-Path $Search) {
            Set-ItemProperty $Search -Name AllowCortana -Value 0 -Verbose
        }
            
        #Stops the Windows Feedback Experience from sending anonymous data
        Write-Output "Stopping the Windows Feedback Experience program"
        $Period1 = 'HKCU:\Software\Microsoft\Siuf'
        $Period2 = 'HKCU:\Software\Microsoft\Siuf\Rules'
        $Period3 = 'HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds'
        If (!(Test-Path $Period3)) { 
            mkdir $Period1 -ErrorAction SilentlyContinue
            mkdir $Period2 -ErrorAction SilentlyContinue
            mkdir $Period3 -ErrorAction SilentlyContinue
            New-ItemProperty $Period3 -Name PeriodInNanoSeconds -Value 0 -Verbose -ErrorAction SilentlyContinue
        }
                   
        Write-Output "Adding Registry key to prevent bloatware apps from returning"
        #Prevents bloatware applications from returning
        $registryPath = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
        If (!(Test-Path $registryPath)) {
            Mkdir $registryPath -ErrorAction SilentlyContinue
            New-ItemProperty $registryPath -Name DisableWindowsConsumerFeatures -Value 1 -Verbose -ErrorAction SilentlyContinue
        }          
        
        Write-Output "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
        $Holo = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic'    
        If (Test-Path $Holo) {
            Set-ItemProperty $Holo -Name FirstRunSucceeded -Value 0 -Verbose
        }
        
        #Disables live tiles
        Write-Output "Disabling live tiles"
        $Live = 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'    
        If (!(Test-Path $Live)) {
            mkdir $Live -ErrorAction SilentlyContinue     
            New-ItemProperty $Live -Name NoTileApplicationNotification -Value 1 -Verbose
        }
        
        #Turns off Data Collection via the AllowTelemtry key by changing it to 0
        Write-Output "Turning off Data Collection"
        $DataCollection = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection'    
        If (Test-Path $DataCollection) {
            Set-ItemProperty $DataCollection -Name AllowTelemetry -Value 0 -Verbose
        }
        
        #Disables People icon on Taskbar
        Write-Output "Disabling People icon on Taskbar"
        $People = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
        If (Test-Path $People) {
            Set-ItemProperty $People -Name PeopleBand -Value 0 -Verbose
        }
    
        #Disables suggestions on start menu
        Write-Output "Disabling suggestions on the Start Menu"
        $Suggestions = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'    
        If (Test-Path $Suggestions) {
            Set-ItemProperty $Suggestions -Name SystemPaneSuggestionsEnabled -Value 0 -Verbose
        }
        
        
        Write-Output "Removing CloudStore from registry if it exists"
        $CloudStore = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore'
        If (Test-Path $CloudStore) {
            Stop-Process -Force Explorer.exe -Force
            Remove-Item $CloudStore -Recurse -Force
            Start-Process Explorer.exe -Wait
        }
    
        #Loads the registry keys/values below into the NTUSER.DAT file which prevents the apps from redownloading. Credit to a60wattfish
        reg load HKU\Default_User C:\Users\Default\NTUSER.DAT
        Set-ItemProperty -Path Registry::HKU\Default_User\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Value 0
        Set-ItemProperty -Path Registry::HKU\Default_User\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name PreInstalledAppsEnabled -Value 0
        Set-ItemProperty -Path Registry::HKU\Default_User\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name OemPreInstalledAppsEnabled -Value 0
        reg unload HKU\Default_User
        
        #Disables scheduled tasks that are considered unnecessary 
        Write-Output "Disabling scheduled tasks"
        #Get-ScheduledTask -TaskName XblGameSaveTaskLogon | Disable-ScheduledTask -ErrorAction SilentlyContinue
        #Get-ScheduledTask -TaskName XblGameSaveTask | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
        
    }    
}
else {
    Write-Output "The Privacy Section Was Skipped..."
}

if ($imagecleanup -eq $true) {
    Write-Host "Cleaning Up Install Files and Cleanining Up the Image" -ForegroundColor Green
    Start-Job -Name "Image Cleanup" -ScriptBlock {
        #Delete "windows.old" folder
        # command currently also deletes restore points
        #Cmd.exe /c Cleanmgr /sageset:65535 
        #Cmd.exe /c Cleanmgr /sagerun:65535
        Write-Verbose "Removing .tmp, .etl, .evtx, thumbcache*.db, *.log files not in use"
        Get-ChildItem -Path c:\ -Include *.tmp, *.dmp, *.etl, *.evtx, thumbcache*.db, *.log -File -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue
        #Delete "RetailDemo" content (if it exits)
        Write-Verbose "Removing Retail Demo content (if it exists)"
        Get-ChildItem -Path $env:ProgramData\Microsoft\Windows\RetailDemo\* -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -ErrorAction SilentlyContinue
        #Delete not in-use anything in the C:\Windows\Temp folder
        Write-Verbose "Removing all files not in use in $env:windir\TEMP"
        Remove-Item -Path $env:windir\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
        #Clear out Windows Error Reporting (WER) report archive folders
        Write-Verbose "Cleaning up WER report archive"
        Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportArchive\* -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportQueue\* -Recurse -Force -ErrorAction SilentlyContinue
        #Delete not in-use anything in your $env:TEMP folder
        Write-Verbose "Removing files not in use in $env:TEMP directory"
        Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
        #Clear out ALL visible Recycle Bins
        Write-Verbose "Clearing out ALL Recycle Bins"
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        #Clear out BranchCache cache
        Write-Verbose "Clearing BranchCache cache"
        Clear-BCCache -Force -ErrorAction SilentlyContinue
        #Clear volume backups (shadow copies)
        #vssadmin delete shadows /all /quiet
        #Empty trash bin
        Powershell -Command "$bin = (New-Object -ComObject Shell.Application).NameSpace(10);$bin.items() | ForEach { Write-Host "Deleting $($_.Name) from Recycle Bin"; Remove-Item $_.Path -Recurse -Force}"
        #Delete controversial default0 user
        net user defaultuser0 /delete 2>nul
        #Clear thumbnail cache
        Remove-Item /f /s /q /a $env:LocalAppData\Microsoft\Windows\Explorer\*.db
        #Clear Windows temp files
        Remove-Item /f /q $env:localappdata\Temp\*
        Remove-Item /s /q "$env:WINDIR\Temp"
        Remove-Item /s /q "$env:TEMP"
        #Clear main telemetry file
        takeown /f "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /r -Value y
        icacls "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /grant administrators:F /t
        Write-Output"" > "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
        Write-Output Clear successful: "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
        #Clear Distributed Transaction Coordinator logs
        Remove-Item /f /q $env:SystemRoot\DtcInstall.log
        #Clear Optional Component Manager and COM+ components logs
        Remove-Item /f /q $env:SystemRoot\comsetup.log
        #Clear Pending File Rename Operations logs
        Remove-Item /f /q $env:SystemRoot\PFRO.log
        #Clear Windows Deployment Upgrade Process Logs
        Remove-Item /f /q $env:SystemRoot\setupact.log
        Remove-Item /f /q $env:SystemRoot\setuperr.log
        #Clear Windows Setup Logs
        Remove-Item /f /q $env:SystemRoot\setupapi.log
        Remove-Item /f /q $env:SystemRoot\Panther\*
        Remove-Item /f /q $env:SystemRoot\inf\setupapi.app.log
        Remove-Item /f /q $env:SystemRoot\inf\setupapi.dev.log
        Remove-Item /f /q $env:SystemRoot\inf\setupapi.offline.log
        #Clear Windows System Assessment Tool logs
        Remove-Item /f /q $env:SystemRoot\Performance\WinSAT\winsat.log
        #Clear Password change events
        Remove-Item /f /q $env:SystemRoot\debug\PASSWD.LOG
        #Clear user web cache database
        Remove-Item /f /q $env:LocalAppData\Microsoft\Windows\WebCache\*.*
        #Clear system temp folder when noone is logged in
        Remove-Item /f /q $env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\Temp\*.*
        #Clear DISM (Deployment Image Servicing and Management) Logs
        Remove-Item /f /q  $env:SystemRoot\Logs\CBS\CBS.log
        Remove-Item /f /q  $env:SystemRoot\Logs\DISM\DISM.log
        #Clear Server-initiated Healing Events Logs
        Remove-Item /f /q "$env:SystemRoot\Logs\SIH\*"
        #Common Language Runtime Logs
        Remove-Item /f /q "$env:LocalAppData\Microsoft\CLR_v4.0\UsageTraces\*"
        Remove-Item /f /q "$env:LocalAppData\Microsoft\CLR_v4.0_32\UsageTraces\*"
        #Network Setup Service Events Logs
        Remove-Item /f /q "$env:SystemRoot\Logs\NetSetup\*"
        #Disk Cleanup tool (Cleanmgr.exe) Logs
        Remove-Item /f /q "$env:SystemRoot\System32\LogFiles\setupcln\*"
        #Clear Windows update and SFC scan logs
        Remove-Item /f /q $env:SystemRoot\Temp\CBS\*
        #Clear Windows Update Medic Service logs
        takeown /f $env:SystemRoot\Logs\waasmedic /r -Value y
        icacls $env:SystemRoot\Logs\waasmedic /grant administrators:F /t
        Remove-Item /s /q $env:SystemRoot\Logs\waasmedic
        #Clear Cryptographic Services Traces
        Remove-Item /f /q $env:SystemRoot\System32\catroot2\dberr.txt
        Remove-Item /f /q $env:SystemRoot\System32\catroot2.log
        Remove-Item /f /q $env:SystemRoot\System32\catroot2.jrs
        Remove-Item /f /q $env:SystemRoot\System32\catroot2.edb
        Remove-Item /f /q $env:SystemRoot\System32\catroot2.chk
        #Windows Update Events Logs
        Remove-Item /f /q "$env:SystemRoot\Logs\SIH\*"
        #Windows Update Logs
        Remove-Item /f /q "$env:SystemRoot\Traces\WindowsUpdate\*"
        #Clear Internet Explorer traces
        Remove-Item /f /q "$env:LocalAppData\Microsoft\Windows\INetCache\IE\*"
        reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" /va /f
        reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLsTime" /va /f
        Remove-Item /s /q "$env:LocalAppData\Microsoft\Internet Explorer"
        Remove-Item /s /q "$env:APPDATA\Microsoft\Windows\Cookies"
        Remove-Item /s /q "$env:USERPROFILE\Cookies"
        Remove-Item /s /q "$env:USERPROFILE\Local Settings\Traces"
        Remove-Item /s /q "$env:LocalAppData\Temporary Internet Files"
        Remove-Item /s /q "$env:LocalAppData\Microsoft\Windows\Temporary Internet Files"
        Remove-Item /s /q "$env:LocalAppData\Microsoft\Windows\INetCookies\PrivacIE"
        Remove-Item /s /q "$env:LocalAppData\Microsoft\Feeds Cache"
        Remove-Item /s /q "$env:LocalAppData\Microsoft\InternetExplorer\DOMStore"
        #Clear Google Chrome traces
        Remove-Item /f /q "$env:LocalAppData\Google\Software Reporter Tool\*.log"
        Remove-Item /s /q "$env:USERPROFILE\Local Settings\Application Data\Google\Chrome\User Data"
        Remove-Item /s /q "$env:LocalAppData\Google\Chrome\User Data"
        Remove-Item /s /q "$env:LocalAppData\Google\CrashReports\"
        Remove-Item /s /q "$env:LocalAppData\Google\Chrome\User Data\Crashpad\reports\"
        #Clear Opera traces
        Remove-Item /s /q "$env:USERPROFILE\AppData\Local\Opera\Opera"
        Remove-Item /s /q "$env:APPDATA\Opera\Opera"
        Remove-Item /s /q "$env:USERPROFILE\Local Settings\Application Data\Opera\Opera"
        #Clear Safari traces
        Remove-Item /s /q "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\Traces"
        Remove-Item /s /q "$env:APPDATA\Apple Computer\Safari"
        Remove-Item /q /s /f "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\Cache.db"
        Remove-Item /q /s /f "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\WebpageIcons.db"
        Remove-Item /s /q "$env:USERPROFILE\Local Settings\Application Data\Apple Computer\Safari\Traces"
        Remove-Item /q /s /f "$env:USERPROFILE\Local Settings\Application Data\Apple Computer\Safari\Cache.db"
        Remove-Item /q /s /f "$env:USERPROFILE\Local Settings\Application Data\Safari\WebpageIcons.db"
        #Clear Listary indexes
        Remove-Item /f /s /q $env:APPDATA\Listary\UserData > nul
        #Clear Java cache
        Remove-Item /s /q "$env:APPDATA\Sun\Java\Deployment\cache"
        #Clear Flash traces
        Remove-Item /s /q "$env:APPDATA\Macromedia\Flash Player"
        #Clear Steam dumps, logs and traces
        Remove-Item /f /q %ProgramFiles(x86)%\Steam\Dumps
        Remove-Item /f /q %ProgramFiles(x86)%\Steam\Traces
        Remove-Item /f /q %ProgramFiles(x86)%\Steam\appcache\*.log
        #Clear Visual Studio telemetry and feedback data
        Remove-Item /s /q "$env:APPDATA\vstelemetry" 2>nul
        Remove-Item /s /q "$env:LocalAppData\Microsoft\VSApplicationInsights" 2>nul
        Remove-Item /s /q "$env:ProgramData\Microsoft\VSApplicationInsights" 2>nul
        Remove-Item /s /q "$env:TEMP\Microsoft\VSApplicationInsights" 2>nul
        Remove-Item /s /q "$env:TEMP\VSFaultInfo" 2>nul
        Remove-Item /s /q "$env:TEMP\VSFeedbackPerfWatsonData" 2>nul
        Remove-Item /s /q "$env:TEMP\VSFeedbackVSRTCLogs" 2>nul
        Remove-Item /s /q "$env:TEMP\VSRemoteControl" 2>nul
        Remove-Item /s /q "$env:TEMP\VSTelem" 2>nul
        Remove-Item /s /q "$env:TEMP\VSTelem.Out" 2>nul
        #Clear Dotnet CLI telemetry
        Remove-Item /s /q "$env:USERPROFILE\.dotnet\TelemetryStorageService" 2>nul
        #Clear regedit last key
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
        #Clear regedit favorites
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
        #Clear list of recent programs opened
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /va /f
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy" /va /f
        #Clear Adobe Media Browser MRU
        reg delete "HKCU\Software\Adobe\MediaBrowser\MRU" /va /f
        #Clear MSPaint MRU
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
        #Clear Wordpad MRU
        reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List" /va /f
        #Clear Map Network Drive MRU MRU
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
        #Clear Windows Search Assistant history
        reg delete "HKCU\Software\Microsoft\Search Assistant\ACMru" /va /f
        #Clear list of Recent Files Opened, by Filetype
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
        reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU" /va /f
        #Clear windows media player recent files and urls
        reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
        reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
        #Clear Most Recent Application's Use of DirectX
        reg delete "HKCU\Software\Microsoft\Direct3D\MostRecentApplication" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\Direct3D\MostRecentApplication" /va /f
        #Clear Windows Run MRU & typedpaths
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f
        reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /va /f
        #Clear recently accessed files
        Remove-Item /f /q "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*"
        #Clear user pins
        Remove-Item /f /q "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*"
        #Clear regedit last key
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
    }
}
else {
    Write-Output "The Image Cleanup Section Was Skipped..."
}

if ($nessusPID -eq $true) {
    Write-Host "Resolve: Nessus Plugin ID 63155 - Microsoft Windows Unquoted Service Path Enumeration" -ForegroundColor Green
    Start-Job -Name "Nessus Plugin ID 63155 - Microsoft Windows Unquoted Service Path Enumeration" -ScriptBlock {
        # https://github.com/VectorBCO/windows-path-enumerate/blob/development/Windows_Path_Enumerate.ps1
        ForEach ($i in 1..2) {
            # Get all services
            $FixParameters = @()
            If ($i = 1) {
                $FixParameters += @{"Path" = "HKLM:\SYSTEM\CurrentControlSet\Services\" ; "ParamName" = "ImagePath" }
            }
            If ($i = 2) {
                $FixParameters += @{"Path" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString" }
                # If OS x64 - adding paths for x86 programs
                If (Test-Path "$($env:SystemDrive)\Program Files (x86)\") {
                    $FixParameters += @{"Path" = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString" }
                }
            }
            $PTElements = @()
            ForEach ($FixParameter in $FixParameters) {
                Get-ChildItem $FixParameter.Path -ErrorAction SilentlyContinue | ForEach-Object {
                    $SpCharREGEX = '([\[\]])'
                    $RegistryPath = $_.name -Replace 'HKEY_LOCAL_MACHINE', 'HKLM:' -replace $SpCharREGEX, '`$1'
                    $OriginalPath = (Get-ItemProperty "$RegistryPath")
                    $ImagePath = $OriginalPath.$($FixParameter.ParamName)
                    If ($i = 1, 2) {
                        If ($($OriginalPath.$($FixParameter.ParamName)) -match '%(?''envVar''[^%]+)%') {
                            $EnvVar = $Matches['envVar']
                            $FullVar = (Get-ChildItem env: | Where-Object { $_.Name -eq $EnvVar }).value
                            $ImagePath = $OriginalPath.$($FixParameter.ParamName) -replace "%$EnvVar%", $FullVar
                            Clear-Variable Matches
                        } # End If
                    } # End If $fixEnv
                    # Get all services with vulnerability
                    If (($ImagePath -like "* *") -and ($ImagePath -notLike '"*"*') -and ($ImagePath -like '*.exe*')) {
                        # Skip MsiExec.exe in uninstall strings
                        If ((($FixParameter.ParamName -eq 'UninstallString') -and ($ImagePath -NotMatch 'MsiExec(\.exe)?') -and ($ImagePath -Match '^((\w\:)|(%[-\w_()]+%))\\')) -or ($FixParameter.ParamName -eq 'ImagePath')) {
                            $NewPath = ($ImagePath -split ".exe ")[0]
                            $key = ($ImagePath -split ".exe ")[1]
                            $trigger = ($ImagePath -split ".exe ")[2]
                            $NewValue = ''
                            # Get service with vulnerability with key in ImagePath
                            If (-not ($trigger | Measure-Object).count -ge 1) {
                                If (($NewPath -like "* *") -and ($NewPath -notLike "*.exe")) {
                                    $NewValue = "`"$NewPath.exe`" $key"
                                } # End If
                                # Get service with vulnerability with out key in ImagePath
                                ElseIf (($NewPath -like "* *") -and ($NewPath -like "*.exe")) {
                                    $NewValue = "`"$NewPath`""
                                } # End ElseIf
                                If ((-not ([string]::IsNullOrEmpty($NewValue))) -and ($NewPath -like "* *")) {
                                    try {
                                        $soft_service = $(if ($FixParameter.ParamName -Eq 'ImagePath') { 'Service' }Else { 'Software' })
                                        $OriginalPSPathOptimized = $OriginalPath.PSPath -replace $SpCharREGEX, '`$1'
                                        Write-Host "$(get-date -format u)  :  Old Value : $soft_service : '$($OriginalPath.PSChildName)' - $($OriginalPath.$($FixParameter.ParamName))"
                                        Write-Host "$(get-date -format u)  :  Expected  : $soft_service : '$($OriginalPath.PSChildName)' - $NewValue"
                                        if ($Passthru) {
                                            $PTElements += '' | Select-Object `
                                            @{n = 'Name'; e = { $OriginalPath.PSChildName } }, `
                                            @{n = 'Type'; e = { $soft_service } }, `
                                            @{n = 'ParamName'; e = { $FixParameter.ParamName } }, `
                                            @{n = 'Path'; e = { $OriginalPSPathOptimized } }, `
                                            @{n = 'OriginalValue'; e = { $OriginalPath.$($FixParameter.ParamName) } }, `
                                            @{n = 'ExpectedValue'; e = { $NewValue } }
                                        }
                                        If (! ($i -gt 2)) {
                                            Set-ItemProperty -Path $OriginalPSPathOptimized -Name $($FixParameter.ParamName) -Value $NewValue -ErrorAction Stop
                                            $DisplayName = ''
                                            $keyTmp = (Get-ItemProperty -Path $OriginalPSPathOptimized)
                                            If ($soft_service -match 'Software') {
                                                $DisplayName = $keyTmp.DisplayName
                                            }
                                            If ($keyTmp.$($FixParameter.ParamName) -eq $NewValue) {
                                                Write-Host "$(get-date -format u)  :  SUCCESS  : Path value was changed for $soft_service '$($OriginalPath.PSChildName)' $(if($DisplayName){"($DisplayName)"})"
                                            } # End If
                                            Else {
                                                Write-Host "$(get-date -format u)  :  ERROR  : Something is going wrong. Path was not changed for $soft_service '$(if($DisplayName){$DisplayName}else{$OriginalPath.PSChildName})'."
                                            } # End Else
                                        } # End If
                                    } # End try
                                    Catch {
                                        Write-Host "$(get-date -format u)  :  ERROR  : Something is going wrong. Value changing failed in service '$($OriginalPath.PSChildName)'."
                                        Write-Host "$(get-date -format u)  :  ERROR  : $_"
                                    } # End Catch
                                    Clear-Variable NewValue
                                } # End If
                            } # End Main If
                        } # End if (Skip not needed strings)
                    } # End If
                    If (($trigger | Measure-Object).count -ge 1) {
                        Write-Host "$(get-date -format u)  :  ERROR  : Can't parse  $($OriginalPath.$($FixParameter.ParamName)) in registry  $($OriginalPath.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry\:\:') "
                    } # End If
                } # End Foreach
            } # End Foreach
        } # End Foreach   
    } # End Job
}
else {
    Write-Output "The Nessus PID 63155 Section Was Skipped..."
}

if ($sysmon -eq $true) {
    Write-Host "Implementing simeononsecurity/Automate-Sysmon" -ForegroundColor Green
    Write-Host "https://github.com/simeononsecurity/Automate-Sysmon" -ForegroundColor Green 

    Start-Process "$($PSScriptRoot)\Files\Sysmon\sysmon.exe" -ArgumentList "-u" -WindowStyle Hidden 
    Start-Process "$($PSScriptRoot)\Files\Sysmon\sysmon.exe"  -ArgumentList "-accepteula -i $PSScriptRoot\Files\Sysmon\sysmonconfig-export.xml" -WindowStyle Hidden 
}
else {
    Write-Output "The Install and Configure Sysmon Section Was Skipped..."
}

if ($diskcompression -eq $true) {
    Write-Host "Compressing Disk to Save Space" -ForegroundColor Green
    #Enable Disk Compression and Disable File Indexing
    Start-Job -Name "Enable Disk Compression and Disable File Indexing" -ScriptBlock {
        $DriveLetters = (Get-WmiObject -Class Win32_Volume).DriveLetter
        ForEach ($Drive in $DriveLetters) {
            If (-not ([string]::IsNullOrEmpty($Drive))) {
                $indexing = $Drive.IndexingEnabled
                #Write-Host "Enabling Disk Compression on the $Drive Drive"
                #Enable-NtfsCompression -Path "$Drive"\ -Recurse
                if ("$indexing" -eq $True) {
                    Write-Host "Disabling File Index on the $Drive Drive"
                    Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$Drive'" | Set-WmiInstance -Arguments @{IndexingEnabled = $False } | Out-Null
                }
            }
        }
    }
}
else {
    Write-Output "The Disk Compression Section Was Skipped..."
}

if ($emet -eq $true) {
    Write-Host "Implementing the EMET Hardening Beyond STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\SoS\EMET"
}
else {
    Write-Output "The EMET Section Was Skipped..."
}

if ($updatemanagement -eq $true) {
    Write-Host "Implementing the SoS Update Management Configurations" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\SoS\Update Management"
}
else {
    Write-Output "The Update Management Section Was Skipped..."
}

if ($deviceguard -eq $true) {
    Write-Host "Implementing the SoS Device Guard Configurations" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\SoS\Device Guard"
}
else {
    Write-Output "The Device Guard Section Was Skipped..."
}

if ($sosbrowsers -eq $true) {
    Write-Host "Implementing the SoS Browser Configurations" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\SoS\Browsers"
}
else {
    Write-Output "The Browsers Config Section Was Skipped..."
}

Write-Host "Checking Backgrounded Processes"; Get-Job

Write-Host "Performing Group Policy Update"
$timeoutSeconds = 180
$gpupdateJob = Start-Job -ScriptBlock { Gpupdate /force }
$gpupdateResult = Receive-Job -Job $gpupdateJob -Wait -Timeout $timeoutSeconds
if ($gpupdateResult -eq $null) {
    Write-Host "Group Policy Update timed out after $timeoutSeconds seconds."
} else {
    Write-Host "Group Policy Update completed."
}

Write-Warning "A reboot is required for all changes to take effect"
