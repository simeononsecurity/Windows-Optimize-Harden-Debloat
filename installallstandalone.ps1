######SCRIPT FOR FULL INSTALL AND CONFIGURE ON STANDALONE MACHINE#####
$ErrorActionPreference= 'silentlycontinue'

Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)


#Unblock all files required for script
start-job -ScriptBlock {ls *.ps*1 -recurse | Unblock-File}

#Copy Files to Required Directories
#Windows 10 Defenter Exploit Guard Configuration File
start-job -ScriptBlock {mkdir C:\temp\; mkdir "C:\temp\Windows Defender"; copy-item -Path .\Files\DOD_EP_V3.xml -Destination "C:\temp\Windows Defender" -Force -Recurse -ErrorAction SilentlyContinue}
#Copy Policy Definitions for gpedit.msc

#Install PowerShell Modules
start-job -ScriptBlock {copy-item -Path .\Files\"PowerShell Modules"\*  -Destination C:\Windows\System32\WindowsPowerShell\v1.0\Modules -Force -Recurse -ErrorAction SilentlyContinue}
#Unblock New PowerShell Modules
start-job -ScriptBlock {Unblock-File -Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PowerSTIG\"; Unblock-File -Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\"; Unblock-File -Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PowerShellAccessControl\"}
#Import New PowerShell Modules
start-job -ScriptBlock {Import-Module -Name PowerSTIG -Force -Global; Import-Module -Name PSWindowsUpdate -Force -Global; Import-Module -Name PowerShellAccessControl -Force -Global}

##Install Latest Windows Updates
start-script -ScriptBlock {Install-WindowsUpdate -MicrosoftUpdate -AcceptAll; Get-WuInstall -AcceptAll -IgnoreReboot; Get-WuInstall -AcceptAll -Install -IgnoreReboot}

#Optional Scripts 
#.\Files\Scripts\"Security, Hardening, and Mitigations"\"SSL Hardening Registries.ps1"
#.\Files\Scripts\"Debloating, Optimization, and Privacy"\"Windows_10_VDI"\1909_WindowsUpdateEnabled\Win10_1909_VDI_Optimize.ps1

#Security Scripts
.\Files\Scripts\"Security, Hardening, and Mitigations"\installadmxtemplates.ps1
.\Files\Scripts\"Security, Hardening, and Mitigations"\"disable tcp timestamps.bat"
.\Files\Scripts\"Security, Hardening, and Mitigations"\"IE Scripting Engine Memory Corruption.bat"
.\Files\Scripts\"Security, Hardening, and Mitigations"\"specture meltdown mitigations.bat"
.\Files\Scripts\"Security, Hardening, and Mitigations"\HardeningKitty\soskitty.ps1
.\Files\Scripts\"Security, Hardening, and Mitigations"\FireFoxConfInstall.ps1

#Debloating Scripts
.\Files\Scripts\"Debloating, Optimization, and Privacy"\"Windows 10 Debloater"\Windows10SysPrepDebloater.ps1 -Sysprep -Debloat -Privacy
.\Files\Scripts\"Debloating, Optimization, and Privacy"\"ultimate performance mode.ps1"
.\Files\Scripts\"Debloating, Optimization, and Privacy"\optimizevmvirtalization.ps1
.\Files\Scripts\"Debloating, Optimization, and Privacy"\startupcleantelem.ps1
.\Files\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\sharpappscripts.ps1
.\Files\Scripts\"Debloating, Optimization, and Privacy"\debotnet\debotnetscripts.ps1
.\Files\Scripts\"Debloating, Optimization, and Privacy"\W4H4Wk\sosw4h4wk.ps1

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