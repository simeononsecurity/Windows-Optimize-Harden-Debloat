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
.\Scripts\"Debloating, Optimization, and Privacy"\"Windows 10 telemetry.ps1"
.\Scripts\"Debloating, Optimization, and Privacy"\ultimate performance mode.ps1
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