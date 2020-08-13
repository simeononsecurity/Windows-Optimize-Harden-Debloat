######SCRIPT FOR FULL INSTALL AND CONFIGURE ON STANDALONE MACHINE#####
#Continue on error
#$ErrorActionPreference= 'silentlycontinue'

#Require elivation for script run
Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

#Unblock all files required for script
Get-ChildItem *.ps*1 -recurse | Unblock-File

#Windows 10 Defenter Exploit Guard Configuration File
start-job -ScriptBlock {mkdir C:\temp\; mkdir "C:\temp\Windows Defender"; copy-item -Path .\Files\DOD_EP_V3.xml -Destination "C:\temp\Windows Defender" -Force -Recurse -ErrorAction SilentlyContinue} 

#Install Required PSModules
.\Files\Scripts\"Package Management and Windows Updates"\sos-installpsmodules.ps1

##Install Latest Windows Updates
start-job -ScriptBlock {Install-WindowsUpdate -MicrosoftUpdate -AcceptAll; Get-WuInstall -AcceptAll -IgnoreReboot; Get-WuInstall -AcceptAll -Install -IgnoreReboot}

#Optional Scripts 
#.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-ssl-hardening.ps1
#.\Files\Scripts\"Debloating, Optimization, and Privacy"\"Windows_10_VDI"\1909_WindowsUpdateEnabled\Win10_1909_VDI_Optimize.ps1

#Customization Scripts
.\Files\Scripts\"Customization and Branding"\sos-copybranding.ps1
.\Files\Scripts\"Customization and Branding"\sos-darkmode.ps1

#Security Scripts
.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-installadmxtemplates.ps1
.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-disable-tcp-timestamps.ps1
.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-specture-meltdown-mitigations.ps1
.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-IE-Scripting-Engine-Memory-Corruption.bat
.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-FireFoxConfInstall.ps1
.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-install-java-config.ps1
#.\Files\Scripts\"Security, Hardening, and Mitigations"\sos-.net-4-stig.ps1

#Debloating Scripts
.\Files\Scripts\"Debloating, Optimization, and Privacy"\"Windows 10 Debloater"\Windows10SysPrepDebloater.ps1 -Sysprep -Debloat -Privacy
.\Files\Scripts\"Debloating, Optimization, and Privacy"\sos-ultimate-performance-mode.ps1
.\Files\Scripts\"Debloating, Optimization, and Privacy"\sos-debloatandoptimize.ps1
.\Files\Scripts\"Debloating, Optimization, and Privacy"\sharpapp\sos-sharpappscripts.ps1
.\Files\Scripts\"Debloating, Optimization, and Privacy"\debotnet\sos-debotnetscripts.ps1
.\Files\Scripts\"Debloating, Optimization, and Privacy"\W4H4Wk\sos-w4h4wk.ps1

#GPO Configurations
.\Files\LGPO\LGPO.exe /g .\Files\GPOs\
