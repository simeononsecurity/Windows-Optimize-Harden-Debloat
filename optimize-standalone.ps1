######SCRIPT FOR FULL INSTALL AND CONFIGURE ON STANDALONE MACHINE#####
#Continue on error
$ErrorActionPreference= 'silentlycontinue'

#Require elivation for script run
#Requires -RunAsAdministrator
Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

#Unblock all files required for script
Get-ChildItem *.ps*1 -recurse | Unblock-File

#Windows 10 Defenter Exploit Guard Configuration File
start-job -ScriptBlock {mkdir "C:\temp\Windows Defender"; copy-item -Path .\Files\"Windows Defender Configuration Files"\DOD_EP_V3.xml -Destination "C:\temp\Windows Defender" -Force -Recurse -ErrorAction SilentlyContinue} 

#Install PowerShell Modules
copy-item -Path .\Files\"PowerShell Modules"\* -Destination C:\Windows\System32\WindowsPowerShell\v1.0\Modules -Force -Recurse
#Unblock New PowerShell Modules
Get-ChildItem C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\ -recurse | Unblock-File
Get-ChildItem C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PowerShellAccessControl\ -recurse | Unblock-File
#Import New PowerShell Modules
Import-Module -Name PSWindowsUpdate -Force -Global
Import-Module -Name PowerShellAccessControl -Force -Global

#Optional Scripts 
#.\Files\Optional\sos-ssl-hardening.ps1
#.\Files\Optional\"Windows_10_VDI"\1909_WindowsUpdateEnabled\Win10_1909_VDI_Optimize.ps1
# powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61

#Disabled - Work In Progress
#.\Files\Optional\sos-.net-4-stig.ps1

#Branding
if (test-path C:\temp\branding){
    Write-host branding files already moved
    }else {
    mkdir C:\temp\Branding
    copy-item -Path .\Files\Branding\* -Destination C:\temp\Branding\ -Recurse -Force
    }
    copy-item -Path .\Files\Branding\wallpaper.jpg -Destination C:\Windows\Web\Screen\lockscreen.jpg -Force
    copy-item -Path .\Files\Branding\wallpaper.jpg -Destination C:\Windows\Web\Wallpaper\Theme1\wallpaper.jpg -Force
    copy-item -Path .\Files\Branding\oemlogo.bmp -Destination "C:\ProgramData\Microsoft\User Account Pictures" -Force
    copy-item -Path .\Files\Branding\user*.png -Destination "C:\ProgramData\Microsoft\User Account Pictures" -Force
    copy-item -Path .\Files\Branding\user*.bmp -Destination "C:\ProgramData\Microsoft\User Account Pictures" -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name Wallpaper -Type String -Value C:\Windows\Web\Wallpaper\Theme1\wallpaper.jpg -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name Logo -Type String -Value "C:\ProgramData\Microsoft\User Account Pictures\oemlogo.bmp" -Force
#Enable Darkmode 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -Type DWORD -Value "00000000" -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name SystemUsesLightTheme -Type DWORD -Value "00000000" -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name ColorPrevalence -Type DWORD -Value "00000000" -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name EnableTransparency -Type DWORD -Value "00000001" -Force

##Install Latest Windows Updates
start-job -ScriptBlock {Install-WindowsUpdate -MicrosoftUpdate -AcceptAll; Get-WuInstall -AcceptAll -IgnoreReboot; Get-WuInstall -AcceptAll -Install -IgnoreReboot}

#Security Scripts
start-job -ScriptBlock {takeown /f C:\WINDOWS\Policydefinitions /r /a; icacls C:\WINDOWS\PolicyDefinitions /grant Administrators:(OI)(CI)F /t; copy-item -Path .\Files\PolicyDefinitions\* -Destination C:\Windows\PolicyDefinitions -Force -Recurse -ErrorAction SilentlyContinue}

#Disable TCP Timestamps
netsh int tcp set global timestamps=disabled

#####SPECTURE MELTDOWN#####
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type DWORD -Value 3 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Type DWORD -Value 8 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type DWORD -Value 3 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Type DWORD -Value 72 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type DWORD -Value 3 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Type DWORD -Value 8264 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type DWORD -Value 3 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -Type String -Value "1.0" -Force

#https://www.itsupportguides.com/knowledge-base/tech-tips-tricks/how-to-customise-firefox-installs-using-mozilla-cfg/
$firefox64 = "C:\Program Files\Mozilla Firefox"
$firefox32 = "C:\Program Files (x86)\Mozilla Firefox"
Write-Output "Installing Firefox Configurations - Please Wait."
Write-Output "Window will close after install is complete"
If (Test-Path -Path $firefox64){
    Copy-Item -Path .\Files\"FireFox Configuration Files"\defaults -Destination $firefox64 -Force -Recurse
    Copy-Item -Path .\Files\"FireFox Configuration Files"\mozilla.cfg -Destination $firefox64 -Force
    Copy-Item -Path .\Files\"FireFox Configuration Files"\local-settings.js -Destination $firefox64 -Force 
    Write-Host "Firefox 64-Bit Configurations Installed"
}Else {
    Write-Host "FireFox 64-Bit Is Not Installed"
}
If (Test-Path -Path $firefox32){
    Copy-Item -Path .\Files\"FireFox Configuration Files"\defaults -Destination $firefox32 -Force -Recurse
    Copy-Item -Path .\Files\"FireFox Configuration Files"\mozilla.cfg -Destination $firefox32 -Force
    Copy-Item -Path .\Files\"FireFox Configuration Files"\local-settings.js -Destination $firefox32 -Force 
    Write-Host "Firefox 32-Bit Configurations Installed"
}Else {
    Write-Host "FireFox 32-Bit Is Not Installed"
}

##JAVA STIG SCRIPT
#https://gist.github.com/MyITGuy/9628895
#http://stu.cbu.edu/java/docs/technotes/guides/deploy/properties.html

#<Windows Directory>\Sun\Java\Deployment\deployment.config
#- or -
#<JRE Installation Directory>\lib\deployment.config

If (Test-Path -Path "C:\Windows\Sun\Java\Deployment\deployment.config"){
    Write-Host "Deployment Config Already Installed"
}Else {
    Mkdir "C:\Windows\Sun\Java\Deployment\"
	New-Item "C:\Windows\Sun\Java\Deployment\deployment.config"
	Set-Content "C:\Windows\Sun\Java\Deployment\deployment.config" "#deployment.config
	deployment.system.config.mandatory=true
	deployment.system.config=C\:\\temp\\java\\deployment.properties"
    Write-Output "Deployment Config Installed"
}
If (Test-Path -Path "C:\temp\JAVA\"){
    Write-Host "Configs Already Deployed"
}Else {
    Mkdir "C:\temp\JAVA"
	New-Item "C:\temp\JAVA\deployment.properties"
	Set-Content "C:\Windows\Sun\Java\Deployment\deployment.config" "#deployment.properties
# Security Tab
# Enable Java content in the browser
deployment.webjava.enabled=true
deployment.webjava.enabled.locked
# Security Level
deployment.security.level=VERY_HIGH
deployment.security.level.locked

# Advanced Tab
# Debugging\Enable tracing
deployment.trace=false
deployment.trace.locked
# Debugging\Enable logging
deployment.log=false
deployment.log.locked
# Debugging\Show applet lifecycle exceptions
deployment.javapi.lifecycle.exception=false
deployment.javapi.lifecycle.exception.locked
# Java console
deployment.console.startup.mode.locked
deployment.console.startup.mode=HIDE
# Default Java for browsers\Microsoft Internet Explorer
deployment.browser.vm.iexplorer=true
deployment.browser.vm.iexplorer.locked
# Default Java for browsers\Mozilla family
deployment.browser.vm.mozilla.locked
deployment.browser.vm.mozilla=true
# Java Plug-in\Enable the next-generation Java Plug-in (requires browser restart)
# This must be done by executing one of the following commands as an administrator:
# [Disable]	- {JREInstallPath}\bin\ssvagent.exe -high -jpisetup -old
# [Enable]	- {JREInstallPath}\bin\ssvagent.exe -high -jpisetup -new
# Shortcut Creation
deployment.javaws.shortcut=ASK_IF_HINTED
deployment.javaws.shortcut.locked
# JNLP File/MIME Association
deployment.javaws.associations=ASK_USER
deployment.javaws.associations.locked
# Application Installation
deployment.javaws.install=IF_HINT
deployment.javaws.install.locked
#JRE Auto-Download
deployment.javaws.autodownload=NEVER
deployment.javaws.autodownload.locked
# Security Execution Environment\Enable granting elevated access to signed apps
# aka. Allow user to grant permissions to signed content
deployment.security.askgrantdialog.show=false
deployment.security.askgrantdialog.show.locked
# Security Execution Environment\Enable granting elevated access to self-signed apps
deployment.security.askgrantdialog.notinca=false
deployment.security.askgrantdialog.notinca.locked
# Security Execution Environment\Show sandbox warning banner
deployment.security.sandbox.awtwarningwindow=true
deployment.security.sandbox.awtwarningwindow.locked
# Security Execution Environment\Allow user to accept JNLP security requests
deployment.security.sandbox.jnlp.enhanced=true
deployment.security.sandbox.jnlp.enhanced.locked
# Security Execution Environment\Don't prompt for client certificate selection when no certificates or only one exists
deployment.security.clientauth.keystore.auto=true
deployment.security.clientauth.keystore.auto.locked
# Security Execution Environment\Warn if site certificate does not match hostname
deployment.security.jsse.hostmismatch.warning=true
deployment.security.jsse.hostmismatch.warning.locked
# Security Execution Environment\Show site certificate from server even if it is valid
deployment.security.https.warning.show=false
deployment.security.https.warning.show.locked
# Mixed code (sandbox vs. trusted) security verification
deployment.security.mixcode=DISABLE
deployment.security.mixcode.locked
# Perform certificate revocation checks on
deployment.security.revocation.check=ALL_CERTIFICATES
deployment.security.revocation.check.locked
# Check for certificate revocation using
# Replaces Advanced Security Settings\Check certificates for revocation using Certificate Revocation List (CRLs)
# [Certificate Revocation List (CRLs)]		- ocsp=false, crl=true
# [Online Certificate Status Protocol (OCSP)]	- ocsp=true, crl=false
# [Bot CRLs and OCSP]				- ocsp=true, crl=true
deployment.security.validation.ocsp=true
deployment.security.validation.ocsp.locked
deployment.security.validation.crl=true
deployment.security.validation.crl.locked
# Advanced Security Settings\Use certificates and keys in browser keystore
deployment.security.browser.keystore.use=true
deployment.security.browser.keystore.use.locked
# Advanced Security Settings\Check certificates for revocation using Certificate Revocation List (CRLs)
# See Check for certificate revocation using
# Advanced Security Settings\Enable list of trusted publishers
deployment.security.pretrust.list=true
deployment.security.pretrust.list.locked
# Advanced Security Settings\Enable blacklist revocation check
deployment.security.blacklist.check=true
deployment.security.blacklist.check.locked
# Advanced Security Settings\Enable caching password for authentication
deployment.security.password.cache=true
deployment.security.password.cache.locked
# Advanced Security Settings\Enable online certifcate validation
deployment.security.revocation.check=NO_CHECK
deployment.security.revocation.check.locked
# Advanced Security Settings\Use SSL 2.0 compatible ClientHello format
deployment.security.SSLv2Hello=false
deployment.security.SSLv2Hello.locked
# Advanced Security Settings\Use SSL 3.0
deployment.security.SSLv3=true
deployment.security.SSLv3.locked
# Advanced Security Settings\Use TLS 1.0
deployment.security.TLSv1=true
deployment.security.TLSv1.locked
# Advanced Security Settings\Use TLS 1.1
deployment.security.TLSv1.1=true
deployment.security.TLSv1.1.locked
# Advanced Security Settings\Use TLS 1.2
deployment.security.TLSv1.2=true
deployment.security.TLSv1.2.locked
# Miscellaneous\Place Java icon in system tray
# Miscellaneous\Java Quick Starter
deployment.system.tray.icon=false
deployment.system.tray.icon.locked
#V-66963 - Actions enforced before executing mobile code include, for example, prompting users prior to opening email attachments and disabling automatic execution.
deployment.insecure.jres=prompt
deployment.insecure.jres.locked
# Screen: Your Java version is insecure. or Your Java version is out of date.
deployment.expiration.check.enabled=false
deployment.expiration.check.enabled.locked
#
deployment.capture.mime.types=true
deployment.capture.mime.types.locked

deployment.security.expired.warning=false
deployment.security.expired.warning.locked

deployment.user.security.exception.sites=C\:\\temp\\java\\exception.sites


## Optimizations
deployment.system.cachedir=C\:\\temp\\java\\cache\\
deployment.cache.max.size=-1
deployment.cache.jarcompression=9
deployment.javapi.cache.enabled=true"

	New-Item "C:\temp\JAVA\exception.sites"
	Set-Content "C:\Windows\Sun\Java\Deployment\deployment.config" 
	"https://29PALMSBOMI-NSN.GOV
https://ABSENTEESHAWNEETRIBE-NSN.GOV
https://ACCESS-BOARD.GOV
https://ACOM.MIL
https://ADLNET.GOV
https://AF.MIL
https://AFIRM.MIL
https://AFMC.MIL
https://AFMS.MIL
https://AFRH.GOV
https://AFRICOM.MIL
https://AFSPC.MIL
https://AFTAC.GOV
https://AG.GOV
https://AGILE.MIL
https://AGUACALIENTE-NSN.GOV
https://AH.MIL
https://AHRQ.GOV
https://ALASKA.GOV
https://ALTUSANDC.GOV
https://ANTHRAX.MIL
https://APPS.MIL
https://ARCHIVES.GOV
https://ARL.MIL
https://ARLINGTONCEMETERY.MIL
https://ARMY.MIL
https://ARPA.MIL
https://ASBCA.MIL
https://ASSIST.MIL
https://ATF.GOV
https://AVIATIONWEATHER.GOV
https://BADRIVER-NSN.GOV
https://BARONA-NSN.GOV
https://BEARRIVER-NSN.GOV
https://BIA.GOV
https://BIGVALLEYRANCHERIA-NSN.GOV
https://BIHASITKA-NSN.GOV
https://BIOMETRICS.GOV
https://BLM.GOV
https://BLS.GOV
https://BLUELAKERANCHERIA-NSN.GOV
https://BOISFORTE-NSN.GOV
https://BPN.GOV
https://BRAC.GOV
https://BRB-NSN.GOV
https://BTA.MIL
https://BTO.GOV
https://BTS.GOV
https://BURNSPAIUTE-NSN.GOV
https://CA.GOV
https://CABAZONINDIANS-NSN.GOV
https://CAC.MIL
https://CADDONATION-NSN.GOV
https://CALIFORNIAVALLEYMIWOKTRIBE-NSN.GOV
https://CAMPO-NSN.GOV
https://CANCER.GOV
https://CAPITOL.GOV
https://CAPMED.MIL
https://CAYUGANATION-NSN.GOV
https://CBO.GOV
https://CCR.GOV
https://CDATRIBE-NSN.GOV
https://CDC.GOV
https://CENSUS.GOV
https://CENTCOM.MIL
https://CERT.MIL
https://CES.MIL
https://CFPB.GOV
https://CFTC.GOV
https://CHEROKEE-NSN.GOV
https://CHEYENNERIVERSIOUXTRIBE-NSN.GOV
https://CHICKASAW-GOVERNMENT-NSN.GOV
https://CHICKASAW-NSN.GOV
https://CHICKASAWARTISANS-NSN.GOV
https://CHICKASAWGOVERNMENT-NSN.GOV
https://CHICKASAWJUDICIAL-NSN.GOV
https://CHICKASAWLEGISLATURE-NSN.GOV
https://CHICKASAWNATION-NSN.GOV
https://CHICKASAWTRIBE-NSN.GOV
https://CHILKOOT-NSN.GOV
https://CHITIMACHA.GOV
https://CHUKCHANSI-NSN.GOV
https://CIA.GOV
https://CIGIE.GOV
https://CIO.GOV
https://CJIS.GOV
https://CMS.GOV
https://CMTS.GOV
https://CNCS.GOV
https://CNSS.GOV
https://COLUSA-NSN.GOV
https://COMMERCE.GOV
https://COMPLIANCE.GOV
https://COPYRIGHT.GOV
https://COUNTERWMD.GOV
https://COYOTEVALLEY-NSN.GOV
https://CPARS.GOV
https://CPSC.GOV
https://CRHC-NSN.GOV
https://CRIT-NSN.GOV
https://CROW-NSN.GOV
https://CRST-NSN.GOV
https://CSB.GOV
https://CSOSA.GOV
https://CST-NSN.GOV
https://CTTSO.GOV
https://CYBERCOM.MIL
https://DAPS.MIL
https://DARPA.MIL
https://DAU.MIL
https://DC3.MIL
https://DCAA.MIL
https://DCMA.MIL
https://DCOE.MIL
https://DCSA.MIL
https://DEA.GOV
https://DECA.MIL
https://DEFENDAMERICA.MIL
https://DEFENSE.GOV
https://DEFENSEIMAGERY.MIL
https://DEFENSEINNOVATIONMARKETPLACE.MIL
https://DEFENSELINK.MIL
https://DELAWARE.GOV
https://DEPLOYMENTHEALTH.MIL
https://DEPS.MIL
https://DFAS.MIL
https://DHHS.GOV
https://DHRA.MIL
https://DHS.GOV
https://DIA.MIL
https://DISA.MIL
https://DISAGRID.MIL
https://DLA.MIL
https://DMA.MIL
https://DMDC.MIL
https://DMDC.MIL
https://DMSO.MIL
https://DNFSB.GOV
https://DNI.GOV
https://DOC.GOV
https://DOD.GOV
https://DOD.MIL
https://DODED.MIL
https://DODIG.MIL
https://DODIIS.MIL
https://DODLIVE.MIL
https://DODTECHIPEDIA.MIL
https://DOE.GOV
https://DOI.GOV
https://DOL.GOV
https://DOT.GOV
https://DPAA.MIL
https://DRA.GOV
https://DROUGHT.GOV
https://DSCA.MIL
https://DSM.MIL
https://DSS.MIL
https://DTEPI.MIL
https://DTIC.MIL
https://DTRA.MIL
https://DTSA.MIL
https://EACLEARINGHOUSE.GOV
https://EB.MIL
https://ED.GOV
https://EEOC.GOV
https://EKLUTNA-NSN.GOV
https://ELYSHOSHONETRIBE-NSN.GOV
https://EMPLOYEESEXPRESS.GOV
https://EOP.GOV
https://EPA.GOV
https://EPLS.GOV
https://ERDC.GOV
https://ESGR.MIL
https://ESI.MIL
https://ESTOO-NSN.GOV
https://EUCOM.MIL
https://EWIIAAPAAYP-NSN.GOV
https://EXIM.GOV
https://EYAK-NSN.GOV
https://FAA.GOV
https://FBI.GOV
https://FBO.GOV
https://FCA.GOV
https://FCC.GOV
https://FCG.GOV
https://FCP-NSN.GOV
https://FCPOTAWATOMI-NSN.GOV
https://FDA.GOV
https://FDIC.GOV
https://FEC.GOV
https://FEDERALCOURTS.GOV
https://FEDRAMP.GOV
https://FEDVTE-FSI.GOV
https://FEDWORLD.GOV
https://FEMA.GOV
https://FERC.GOV
https://FERO.GOV
https://FGDC.GOV
https://FHFA.GOV
https://FIRSTGOV.GOV
https://FLRA.GOV
https://FMC.GOV
https://FMCS.GOV
https://FOODSAFETY.GOV
https://FORGE.MIL
https://FORTSILLAPACHE-NSN.GOV
https://FPDS-NG.GOV
https://FPDS.GOV
https://FPKI.GOV
https://FRB.GOV
https://FRCC.GOV
https://FREEDOMAWARD.MIL
https://FRS.GOV
https://FRTIB.GOV
https://FSAFEDS.COM
https://FTBELKNAP-NSN.GOV
https://FTC.GOV
https://FVAP.GOV
https://FWS.GOV
https://GA.GOV
https://GAO.GOV
https://GEODATA.GOV
https://GEOMAC.GOV
https://GILARIVER-NSN.GOV
https://GILARIVERINDIANCOMMUNITY-NSN.GOV
https://GLT-NSN.GOV
https://GOAA.GOV
https://GODATA.GOV
https://GOVBENEFITS.GOV
https://GPO.GOV
https://GPOACCESS.GOV
https://GPS.GOV
https://GSA.GOV
https://GSAADVANTAGE.GOV
https://GUIDELINE.GOV
https://GUNLAKETRIBE-NSN.GOV
https://HANNAHVILLEPOTAWATOMI-NSN.GOV
https://HAVASUPAI-NSN.GOV
https://HEALTH.MIL
https://HEALTHFINDER.GOV
https://HEALTHIERUS.GOV
https://HEIMDATA.GOV
https://HHS.GOV
https://HOOPA-NSN.GOV
https://HOPI-NSN.GOV
https://HOUSE.GOV
https://HPC.MIL
https://HUALAPAI-NSN.GOV
https://HUD.GOV
https://IA.MIL
https://IAD.GOV
https://IARPA-IDEAS.GOV
https://IARPA.GOV
https://ICE.GOV
https://ICH.GOV
https://ICJOINTDUTY.GOV
https://IDAHO.GOV
https://IHS.GOV
https://IIPAYNATION-NSN.GOV
https://INDIANAFFAIRS.GOV
https://INTELINK.GOV
https://INTELLIGENCE.GOV
https://INTERIOR.GOV
https://INTERPOL.GOV
https://IOSS.GOV
https://IRS.GOV
https://ISE.GOV
https://ISLETAPUEBLO-NSN.GOV
https://ITC.GOV
https://ITIS.GOV
https://JACKSONRANCHERIA-NSN.GOV
https://JALIS.MIL
https://JAST.MIL
https://JATDI.MIL
https://JBSA.MIL
https://JCCS.GOV
https://JCMOTF.MIL
https://JCOMTF.MIL
https://JCS.MIL
https://JCSE.MIL
https://JECC.MIL
https://JFCOM.MIL
https://JIEDDO.MIL
https://JLLIS.MIL
https://JOINTMODELS.MIL
https://JS.MIL
https://JSC.MIL
https://JSF.MIL
https://JSIMS.MIL
https://JTDI.MIL
https://JTEN.MIL
https://JTFGNO.MIL
https://JUSTICE.GOV
https://JWAC.MIL
https://JWOD.GOV
https://KAIBABPAIUTE-NSN.GOV
https://KAWAIKA-NSN.GOV
https://KAYENTATOWNSHIP-NSN.GOV
https://KBIC-NSN.GOV
https://KENAITZE-NSN.GOV
https://KEWEENAWBAY-NSN.GOV
https://KNOWLEDGENET.MIL
https://KOREA50.MIL
https://KTIK-NSN.GOV
https://LABOR.GOV
https://LAGUNA-NSN.GOV
https://LAGUNAPUEBLO-NSN.GOV
https://LAJOLLA-NSN.GOV
https://LCO-NSN.GOV
https://LOC.GOV
https://LTBBODAWA-NSN.GOV
https://LUMMI-NSN.GOV
https://MAIL.MIL
https://MARINES.MIL
https://MASHANTUCKET-NSN.GOV
https://MASHANTUCKETPEQUOT-NSN.GOV
https://MASHANTUCKETWESTERNPEQUOT-NSN.GOV
https://MASS.GOV
https://MAX.GOV
https://MC.MIL
https://MCN-NSN.GOV
https://MCRMC.GOV
https://MDA.MIL
https://MECHOOPDA-NSN.GOV
https://MEDICAID.GOV
https://MEDICARE.GOV
https://MEDLINEPLUS.GOV
https://MENOMINEE-NSN.GOV
https://MESAGRANDEBAND-NSN.GOV
https://MESKWAKI-NSN.GOV
https://MICCOSUKEE-NSN.GOV
https://MICMAC-NSN.GOV
https://MIDDLETOWNRANCHERIA-NSN.GOV
https://MILCLOUD.MIL
https://MILITARYONESOURCE.MIL
https://MILLELACSBAND-NSN.GOV
https://MILSUITE.MIL
https://MMS.GOV
https://MO.GOV
https://MOAPABANDOFPAIUTES-NSN.GOV
https://MOHICAN-NSN.GOV
https://MOJAVEDATA.GOV
https://MORONGO-NSN.GOV
https://MPGE-NSN.GOV
https://MPTN-NSN.GOV
https://MSCO.MIL
https://MSHA.GOV
https://MSPB.GOV
https://MT.GOV
https://MTMC.GOV
https://MUSCOGEENATION-NSN.GOV
https://MYPAY.GOV
https://NANO.GOV
https://NARA.GOV
https://NASA.GOV
https://NATIONALGUARD.MIL
https://NAVY.MIL
https://NBC.GOV
https://NCD.GOV
https://NCIHA-NSN.GOV
https://NCIX.GOV
https://NCPC.GOV
https://NCR.GOV
https://NCSC.MIL
https://NCUA.GOV
https://NEA.GOV
https://NEH.GOV
https://NEMI.GOV
https://NFPORS.GOV
https://NFR-NSN.GOV
https://NG.MIL
https://NGA.GOV
https://NGA.MIL
https://NH.GOV
https://NHTSA.GOV
https://NIC.GOV
https://NIC.MIL
https://NIFC.GOV
https://NIGC.GOV
https://NIH.GOV
https://NIMA.MIL
https://NINILCHIKTRIBE-NSN.GOV
https://NIPR.MIL
https://NISQUALLY-NSN.GOV
https://NIST.GOV
https://NLRB.GOV
https://NMB.GOV
https://NMIC.GOV
https://NOAA.GOV
https://NOOKSACK-NSN.GOV
https://NORAD.MIL
https://NORADNORTHCOM.MIL
https://NORTHCOM.MIL
https://NORTHFORKRANCHERIA-NSN.GOV
https://NOSC.MIL
https://NPS.GOV
https://NRC.GOV
https://NRO.GOV
https://NRO.MIL
https://NROJR.GOV
https://NSA.GOV
https://NSEP.GOV
https://NSF.GOV
https://NTIS.GOV
https://NTSB.GOV
https://NVB-NSN.GOV
https://NWBSHOSHONE-NSN.GOV
https://NWS.GOV
https://ODNI.GOV
https://OEA.GOV
https://OHIO.GOV
https://OHKAYOWINGEH-NSN.GOV
https://OMAHA-NSN.GOV
https://OMB.GOV
https://ONEIDA-NSN.GOV
https://ONEIDAINDIANNATION-NSN.GOV
https://ONEIDANATION-NSN.GOV
https://OPIC.GOV
https://OPM.GOV
https://OSAGECONGRESS-NSN.GOV
https://OSAGENATION-NSN.GOV
https://OSC.GOV
https://OSD.MIL
https://OSDBU.GOV
https://OSHA.GOV
https://OSHRC.GOV
https://OSIS.GOV
https://PACOM.MIL
https://PASCUAYAQUI-NSN.GOV
https://PASKENTA-NSN.GOV
https://PAUMA-NSN.GOV
https://PBGC.GOV
https://PCI-NSN.GOV
https://PCSTRAVEL.MIL
https://PDHEALTH.MIL
https://PEACECORPS.GOV
https://PECHANGA-NSN.GOV
https://PENTAGON.GOV
https://PENTAGON.MIL
https://PENTAGONCHANNEL.MIL
https://PEQUOT-NSN.GOV
https://PFPA.MIL
https://PHC-NSN.GOV
https://PICAYUNERANCHERIA-NSN.GOV
https://POARCHCREEKINDIANS-NSN.GOV
https://POKAGONBAND-NSN.GOV
https://POL-NSN.GOV
https://PRC.GOV
https://QVIR-NSN.GOV
https://RAMONA-NSN.GOV
https://RATB.GOV
https://READY.GOV
https://REDCLIFF-NSN.GOV
https://REGULATIONS.GOV
https://ROSEBUDSIOUXTRIBE-NSN.GOV
https://RRB.GOV
https://RST-NSN.GOV
https://RSTWATER-NSN.GOV
https://SACANDFOXNATION-NSN.GOV
https://SAFEXCHANGE.GOV
https://SAMHSA.GOV
https://SANDIA.GOV
https://SANMANUEL-NSN.GOV
https://SANTAANA-NSN.GOV
https://SANTAROSACAHUILLA-NSN.GOV
https://SAPR.MIL
https://SAUK-SUIATTLE-NSN.GOV
https://SBA.GOV
https://SCAT-NSN.GOV
https://SCC-NSN.GOV
https://SCUS.GOV
https://SECRETSERVICE.GOV
https://SEMINOLENATION-NSN.GOV
https://SENATE.GOV
https://SHINNECOCK-NSN.GOV
https://SHOALWATERBAY-NSN.GOV
https://SIGIR.MIL
https://SIR-NSN.GOV
https://SITEIDIQ.GOV
https://SITKATRIBE-NSN.GOV
https://SNO-NSN.GOV
https://SOBOBA-NSN.GOV
https://SOC.MIL
https://SOCDS.MIL
https://SOCOM.MIL
https://SOUTHCOM.MIL
https://SOUTHERNUTE-NSN.GOV
https://SPACECOM.MIL
https://SRMT-NSN.GOV
https://SRPMIC-NSN.GOV
https://SSA.GOV
https://SSS.GOV
https://STATE.GOV
https://STRATCOM.MIL
https://SURGEONGENERAL.GOV
https://SUSANVILLEINDIANRANCHERIA-NSN.GOV
https://SWINOMISH-NSN.GOV
https://SWO-NSN.GOV
https://SYCUAN-NSN.GOV
https://TACHI-YOKUT-NSN.GOV
https://TAMAYA-NSN.GOV
https://TEST.MIL
https://TIME.GOV
https://TMDCI-NSN.GOV
https://TOLC-NSN.GOV
https://TOLOWA-NSN.GOV
https://TONATION-NSN.GOV
https://TRANSCOM.MIL
https://TRANSPORTATION.GOV
https://TREAS.GOV
https://TREASURY.GOV
https://TRICARE.MIL
https://TRS.GOV
https://TSA.GOV
https://TSC.GOV
https://TSP.GOV
https://TSWG.GOV
https://TULALIP-NSN.GOV
https://TULALIPAIR-NSN.GOV
https://TULALIPTRIBES-NSN.GOV
https://TULERIVERTRIBE-NSN.GOV
https://TVA.GOV
https://TWENTYNINEPALMSBOMI-NSN.GOV
https://UGOV.GOV
https://UKB-NSN.GOV
https://UNICOR.GOV
https://UPPERSIOUXCOMMUNITY-NSN.GOV
https://UPPERSKAGIT-NSN.GOV
https://US-CERT.GOV
https://USAF.MIL
https://USAID.GOV
https://USAJOBS.GOV
https://USANDC.GOV
https://USASTAFFING.GOV
https://USBM.GOV
https://USBR.GOV
https://USC.GOV
https://USCAPITAL.GOV
https://USCG.GOV
https://USCG.MIL
https://USCIS.GOV
https://USCP.GOV
https://USDA.GOV
https://USDOJ.GOV
https://USFK.MIL
https://USGCRP.GOV
https://USGS.GOV
https://USHMM.GOV
https://USICH.GOV
https://USITC.GOV
https://USJOBS.GOV
https://USMARSHALS.GOV
https://USMC.MIL
https://USMINT.GOV
https://USMISSION.GOV
https://USOGE.GOV
https://USPHS.GOV
https://USPS.GOV
https://USPSOIG.GOV
https://USPTO.GOV
https://USSS.GOV
https://USTAXCOURT.GOV 
https://USTDA.GOV
https://USTRANSCOM.MIL
https://USTREAS.GOV
https://USUHS.MIL
https://VA.GOV
https://VACCINES.MIL
https://VIEJAS-NSN.GOV
https://VOA.GOV
https://WA.GOV
https://WARRIORCARE.MIL
https://WDOL.GOV
https://WEATHER.GOV
https://WESTERNPEQUOT-NSN.GOV
https://WHITEEARTH-NSN.GOV
https://WHITEHOUSE.GOV
https://WHITEPAGES.MIL
https://WHMO.MIL
https://WHS.MIL
https://WI.GOV
https://WILTONRANCHERIA-NSN.GOV
https://WINNEMUCCAINDIANCOLONYOFNEVADA-NSN.GOV
https://WYANDOTTE-NATION-NSN.GOV
https://YAKAMAFISH-NSN.GOV
https://YAKAMANATION-NSN.GOV
https://YOCHADEHE-NSN.GOV
https://YPT-NSN.GOV"
    Write-Output "JAVA Configs Installed"
}



#Debloating Scripts
#This function finds any AppX/AppXProvisioned package and uninstalls it, except for Freshpaint, Windows Calculator, Windows Store, and Windows Photos.
#Also, to note - This does NOT remove essential system services/software/etc such as .NET framework installations, Cortana, Edge, etc.

#This is the switch parameter for running this script as a 'silent' script, for use in MDT images or any type of mass deployment without user interaction.

param (
  [switch]$Debloat, [switch]$SysPrep
)

Function Begin-SysPrep {

    param([switch]$SysPrep)
        Write-Verbose -Message ('Starting Sysprep Fixes')
 
        # Disable Windows Store Automatic Updates
       <# Write-Verbose -Message "Adding Registry key to Disable Windows Store Automatic Updates"
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
        If (!(Test-Path $registryPath)) {
            Mkdir $registryPath -ErrorAction SilentlyContinue
            New-ItemProperty $registryPath -Name AutoDownload -Value 2 
        }
        Else {
            Set-ItemProperty $registryPath -Name AutoDownload -Value 2 
        }
        #Stop WindowsStore Installer Service and set to Disabled
        Write-Verbose -Message ('Stopping InstallService')
        Stop-Service InstallService 
        #>
 } 

#Creates a PSDrive to be able to access the 'HKCR' tree
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
Function Start-Debloat {
    
    param([switch]$Debloat)

    #Removes AppxPackages
    #Credit to Reddit user /u/GavinEke for a modified version of my whitelist code
    [regex]$WhitelistedApps = 'Microsoft.ScreenSketch|Microsoft.Paint3D|Microsoft.WindowsCalculator|Microsoft.WindowsStore|Microsoft.Windows.Photos|CanonicalGroupLimited.UbuntuonWindows|`
    Microsoft.MicrosoftStickyNotes|Microsoft.MSPaint|Microsoft.WindowsCamera|.NET|Framework|Microsoft.HEIFImageExtension|Microsoft.ScreenSketch|Microsoft.StorePurchaseApp|`
    Microsoft.VP9VideoExtensions|Microsoft.WebMediaExtensions|Microsoft.WebpImageExtension|Microsoft.DesktopAppInstaller'
    Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $WhitelistedApps} | Remove-AppxPackage -ErrorAction SilentlyContinue
    # Run this again to avoid error on 1803 or having to reboot.
    Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $WhitelistedApps} | Remove-AppxPackage -ErrorAction SilentlyContinue
    $AppxRemoval = Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -NotMatch $WhitelistedApps} 
    ForEach ( $App in $AppxRemoval) {
    
        Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName 
        
        }
}

Function Remove-Keys {
        
    Param([switch]$Debloat)    
    
    #These are the registry keys that it will delete.
        
    $Keys = @(
        
        #Remove Background Tasks
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        
        #Windows File
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        
        #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        
        #Scheduled Tasks to delete
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        
        #Windows Protocol Keys
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
           
        #Windows Share Target
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
    
    #This writes the output of each key it is removing and also removes the keys listed above.
    ForEach ($Key in $Keys) {
        Write-Output "Removing $Key from registry"
        Remove-Item $Key -Recurse -ErrorAction SilentlyContinue
    }
}
        
Function Protect-Privacy {
    
    Param([switch]$Debloat)    

    #Creates a PSDrive to be able to access the 'HKCR' tree
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
        
    #Disables Windows Feedback Experience
    Write-Output "Disabling Windows Feedback Experience program"
    $Advertising = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
    If (Test-Path $Advertising) {
        Set-ItemProperty $Advertising -Name Enabled -Value 0 -Verbose
    }
        
    #Stops Cortana from being used as part of your Windows Search Function
    Write-Output "Stopping Cortana from being used as part of your Windows Search Function"
    $Search = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
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
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
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
    $Live = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'    
    If (!(Test-Path $Live)) {
        mkdir $Live -ErrorAction SilentlyContinue     
        New-ItemProperty $Live -Name NoTileApplicationNotification -Value 1 -Verbose
    }
    
    #Turns off Data Collection via the AllowTelemtry key by changing it to 0
    Write-Output "Turning off Data Collection"
    $DataCollection = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'    
    If (Test-Path $DataCollection) {
        Set-ItemProperty $DataCollection -Name AllowTelemetry -Value 0 -Verbose
    }
    
    #Disables People icon on Taskbar
    Write-Output "Disabling People icon on Taskbar"
    $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
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
     Stop-Process Explorer.exe -Force
     Remove-Item $CloudStore -Recurse -Force
     Start-Process Explorer.exe -Wait
    }

    #Loads the registry keys/values below into the NTUSER.DAT file which prevents the apps from redownloading. Credit to a60wattfish
    reg load HKU\Default_User C:\Users\Default\NTUSER.DAT
    Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Value 0
    Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name PreInstalledAppsEnabled -Value 0
    Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name OemPreInstalledAppsEnabled -Value 0
    reg unload HKU\Default_User
    
    #Disables scheduled tasks that are considered unnecessary 
    Write-Output "Disabling scheduled tasks"
    #Get-ScheduledTask -TaskName XblGameSaveTaskLogon | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName XblGameSaveTask | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
}

#This includes fixes by xsisbest
Function FixWhitelistedApps {
    
    Param([switch]$Debloat)
    
    If(!(Get-AppxPackage -AllUsers | Select-Object Microsoft.Paint3D, Microsoft.MSPaint, Microsoft.WindowsCalculator, Microsoft.WindowsStore, Microsoft.MicrosoftStickyNotes, Microsoft.WindowsSoundRecorder, Microsoft.Windows.Photos)) {
    
    #Credit to abulgatz for the 4 lines of code
    Get-AppxPackage -allusers Microsoft.Paint3D | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.MSPaint | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.WindowsCalculator | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.WindowsStore | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.MicrosoftStickyNotes | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.WindowsSoundRecorder | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.Windows.Photos | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"} }
}

Function CheckDMWService {

  Param([switch]$Debloat)
  
If (Get-Service -Name dmwappushservice | Where-Object {$_.StartType -eq "Disabled"}) {
    Set-Service -Name dmwappushservice -StartupType Automatic}

If(Get-Service -Name dmwappushservice | Where-Object {$_.Status -eq "Stopped"}) {
   Start-Service -Name dmwappushservice} 
  }

Function CheckInstallService {
  Param([switch]$Debloat)
          If (Get-Service -Name InstallService | Where-Object {$_.Status -eq "Stopped"}) {  
            Start-Service -Name InstallService
            Set-Service -Name InstallService -StartupType Automatic 
            }
        }

Write-Output "Initiating Sysprep"
Begin-SysPrep
Write-Output "Removing bloatware apps."
Start-Debloat
Write-Output "Removing leftover bloatware registry keys."
Remove-Keys
Write-Output "Checking to see if any Whitelisted Apps were removed, and if so re-adding them."
FixWhitelistedApps
Write-Output "Stopping telemetry, disabling unneccessary scheduled tasks, and preventing bloatware from returning."
Protect-Privacy
#Write-Output "Stopping Edge from taking over as the default PDF Viewer."
#Stop-EdgePDF
CheckDMWService
CheckInstallService
Write-Output "Finished all tasks."

#https://docs.microsoft.com/en-us/windows/privacy/
#https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
#https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds_vdi-recommendations-1909
#https://docs.microsoft.com/en-us/powershell/module/smbshare/set-smbserverconfiguration?view=win10-ps
#SMB Optimizations
Write-Output "setting smb optimizations"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" DisableBandwidthThrottling -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" FileInfoCacheEntriesMax -Value 1024 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" DirectoryCacheEntriesMax -Value 1024 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" FileNotFoundCacheEntriesMax -Value 2048 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" RequireSecuritySignature -Value 256 -Force
Set-SmbServerConfiguration -EnableMultiChannel $true -Force 
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force 
Set-SmbServerConfiguration -RequireSecuritySignature $True -Force 
Set-SmbServerConfiguration -EnableSecuritySignature $True -Force 
Set-SmbServerConfiguration -EncryptData $True -Force 
Set-SmbServerConfiguration -MaxChannelPerSession 16 -Force
Set-SmbServerConfiguration -ServerHidden $False -AnnounceServer $False -Force 
Set-SmbClientConfiguration -EnableLargeMtu $true -Force
Set-SmbClientConfiguration -EnableMultiChannel $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $True -Force
Set-SmbClientConfiguration -EnableSecuritySignature $True -Force
#onedrive
Write-Output "remove onedrive automatic start"
# Remove the automatic start item for OneDrive from the default user profile registry hive
Remove-Item -Path "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\OneDrive.lnk" -Force 
Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Load HKLM\\Temp C:\\Users\\Default\\NTUSER.DAT" -Wait
Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Delete HKLM\\Temp\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run -Name OneDriveSetup -Force" -Wait
Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Unload HKLM\\Temp"
#Disable Cortana
Write-Output "disabling cortona"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowSearchToUseLocation -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name DisableWebSearch -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name ConnectedSearchUseWeb -Type DWORD -Value 0 -Force
#Disable Device Metadata Retrieval
Write-Output "Disable Device Metadata Retrieval"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name PreventDeviceMetadataFromNetwork -Type DWORD -Value 1 -Force
#Disable Find My Device
Write-Output "Disable Find My Device"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" -Name AllowFindMyDevice -Type DWORD -Value 0 -Force
#Disable Font Streaming
Write-Output "Disable Font Streaming"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnableFontProviders -Type DWORD -Value 0 -Force
#Disable Insider Preview Builds
Write-Output "Disable Insider Preview Builds"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name AllowBuildPreview -Type DWORD -Value 0 -Force
#IE Optimizations
Write-Output "IE Optimizations"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name EnabledV9 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -Name PolicyDisableGeolocation -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -Name AutoSuggest -Type String -Value no -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name AllowServicePoweredQSA -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" -Name Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\FlipAhead" -Name Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name BackgroundSyncStatus -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name AllowOnlineTips -Type DWORD -Value 0 -Force
#Restrict License Manager
Write-Output "Restrict License Manager"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LicenseManager" -Name Start -Type DWORD -Value 4 -Force
#Disable Live Tiles
Write-Output "Disable Live Tiles"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoCloudApplicationNotification -Type DWORD -Value 1 -Force
#Disable Windows Mail App
Write-Output "Disable Windows Mail App"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Mail" -Name ManualLaunchAllowed -Type DWORD -Value 0 -Force
#Disable Microsoft Account cloud authentication service
Write-Output "Disable Microsoft Account cloud authentication service"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\wlidsvc" -Name Start -Type DWORD -Value 4 -Force
#Disable Network Connection Status Indicator
#Write-Output "Disable Network Connection Status Indicator"
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name NoActiveProbe -Type DWORD -Value 1 -Force
#Disable Offline Maps
Write-Output "Disable Offline Maps"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name AutoDownloadAndUpdateMapData -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name AllowUntriggeredNetworkTrafficOnSettingsPage -Type DWORD -Value 0 -Force
#Remove Bloatware Windows Apps
Write-Output "Remove Reinstalled Apps"
#Weather App
Write-Output "removing Weather App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.BingWeather"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Money App
Write-Output "removing Money App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.BingFinance"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Sports App
Write-Output "removing Sports App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.BingSports"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Twitter App
Write-Output "removing Twitter App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"*.Twitter"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#XBOX App
Write-Output "removing XBOX App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.XboxApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Sway App
Write-Output "removing Sway App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.Office.Sway"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Onenote App
Write-Output "removing Onenote App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.Office.OneNote"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get Office App
Write-Output "removing Get Office App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.MicrosoftOfficeHub"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get Skype App 
Write-Output "removing skype App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.SkypeApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
##General VM Optimizations
#Auto Cert Update
Write-Output "Auto Cert Update"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" -Name DisableRootAutoUpdate -Type DWORD -Value 0 -Force
#Turn off Let websites provide locally relevant content by accessing my language list
Write-Output "Turn off Let websites provide locally relevant content by accessing my language list"
Set-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Type DWORD -Value 1 -Force
#Turn off Let Windows track app launches to improve Start and search results
Write-Output "Turn off Let Windows track app launches to improve Start and search results"
Set-ItemProperty -Path "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Start_TrackProgs -Type DWORD -Value 0 -Force
#Turn off Let apps use my advertising ID for experiences across apps (turning this off will reset your ID
Write-Output "Turn off Let apps use my advertising ID for experiences across apps (turning this off will reset your ID"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name DisabledByGroupPolicy -Type DWORD -Value 1 -Force
#Turn off Let websites provide locally relevant content by accessing my language list
Write-Output "Turn off Let websites provide locally relevant content by accessing my language list"
Set-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Type DWORD -Value 1 -Force
#Turn off Let apps on my other devices open apps and continue experiences on this device
Write-Output "Turn off Let apps on my other devices open apps and continue experiences on this device"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableCdp -Type DWORD -Value 1 -Force
#Turn off Location for this device
Write-Output "Turn off Location for this device"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsAccessLocation -Type DWORD -Value 2 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name DisableLocation -Type DWORD -Value 1 -Force
#Turn off Windows should ask for my feedback
Write-Output "Turn off Windows should ask for my feedback"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name DoNotShowFeedbackNotifications -Type DWORD -Value 1 -Force
#Turn Off Send your device data to Microsoft
Write-Output "Turn Off Send your device data to Microsoft"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Type DWORD -Value 0 -Force
#Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data
Write-Output "Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKEY_Current_User\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableTailoredExperiencesWithDiagnosticData -Type DWORD -Value 1 -Force
#Turn off Let apps run in the background
Write-Output "Turn off Let apps run in the background"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsRunInBackground -Type DWORD -Value 2 -Force
#Software Protection Platform
#Opt out of sending KMS client activation data to Microsoft
Write-Output "Opt out of sending KMS client activation data to Microsoft"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name NoGenTicket -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name NoAcquireGT -Type DWORD -Value 1 -Force
#Turn off Messaging cloud sync
Write-Output "Turn off Messaging cloud sync"
Set-ItemProperty -Path "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Messaging" -Name CloudServiceSyncEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name DisableSettingSync -Type DWORD -Value 2 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name DisableSettingSyncUserOverride -Type DWORD -Value 1 -Force
#Disable Teredo
#Write-Output "Disable Teredo"
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name Teredo_State -Type String -Value Disabled -Force
#Turn off Connect to suggested open hotspots and Connect to networks shared by my contacts
Write-Output "Turn off Connect to suggested open hotspots and Connect to networks shared by my contacts"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name AutoConnectAllowedOEM -Type DWORD -Value 0 -Force
#Delivery Optimization
Write-Output "Delivery Optimization"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name DODownloadMode -Type DWORD -Value 99 -Force
Get-AppxPackage -allusers *xing* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.XboxApp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.GamingApp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.BingWeather* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft3DViewer* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Twitter* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Getstarted* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Office.Sway* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *spotify* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *bingsports* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.SkypeApp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *WindowsScan* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Print3D* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *CommsPhone* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Messaging* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *empires* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *microsoft.windowscommunicationsapps* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.ZuneMusic* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsMaps* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.3dbuilder* | Remove-AppxPackage -AllUsers
Get-AppxPackage Microsoft3DViewer  Remove-AppxPackage
Get-AppxPackage -allusers *AdobeSystemsIncorporated.AdobePhotoshopExpress* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsAlarms* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Appconnector* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.YourPhone* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Asphalt8Airborne* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *candycrush* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *DolbyLaboratories.DolbyAccess* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.DrawboardPDF* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Facebook* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *FarmHeroesSaga* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.XboxGamingOverlay* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.GetHelp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.BingNews* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Todos* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Whiteboard* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *ConnectivityStore* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *MinecraftUWP* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MixedReality.Portal* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.OneConnect* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.ZuneVideo* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Netflix* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *OneNote* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MSPaint* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *PandoraMediaInc* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *CommsPhone* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *windowsphone* | Remove-AppxPackage -AllUsers
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name CortanaConsent -Type DWORD -Value 0 -Force
Get-AppxPackage *Microsoft.549981C3F5F10* | Remove-AppxPackage
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" -Type String -Value  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search and Cortana application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" -Force
Set-MpPreference -PUAProtection Enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name AUOptions -Type DWORD -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ScheduledInstallDay -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ScheduledInstallTime -Type DWORD -Value 3 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update" -Name ExcludeWUDriversInQualityUpdate -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update" -Name ExcludeWUDriversInQualityUpdate -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdates" -Name Value -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name ExcludeWUDriversInQualityUpdate -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name ExcludeWUDriversInQualityUpdate -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type String -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type String -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name Debugger -Type String -Value "%windir%\System32\taskkill.exe" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type String -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name DisableOnline -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID44231 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID64640 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID66610 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" -Name OptInOrOutPreference -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" -Name Start -Type DWORD -Value 4 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name BlockThirdPartyCookies -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name AutofillCreditCardEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name SyncDisabled -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" -Name Debugger -Type String -Value "%windir%\System32\taskkill.exe" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name BackgroundModeEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft" -Name DoNotUpdateToEdgeWithChromium -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name AllowgameDVR -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type DWORD -Value 0 -Force
Stop-Service "LogiRegistryService"
Set-Service  "LogiRegistryService" -StartupType Disabled
Stop-Service "Razer Game Scanner Service"
Set-Service  "Razer Game Scanner Service" -StartupType Disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name DisablePasswordReveal -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Adobe\Adobe ARM\1.0\ARM" -Name "iCheck" -Type String -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "cSharePoint" -Type String -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeDocumentServices" -Type String -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeSign" -Type String -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bTogglePrefSync" -Type String -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleWebConnectors" -Type String -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bAdobeSendPluginToggle" -Type String -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bUpdater" -Type String -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HomeScreen" -Type String -Value 2 -Force
schtasks /Change /TN "DropboxUpdateTaskMachineCore" /disable
schtasks /Change /TN "DropboxUpdateTaskMachineUA" /disable
schtasks /Change /TN "GoogleUpdateTaskMachineCore" /disable
schtasks /Change /TN "GoogleUpdateTaskMachineUA" /disable
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name "Enablelogging" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name "EnableUpload" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\wlidsvc" -Name Start -Type DWORD -Value 4 -Force
Set-Service  wlidsvc -StartupType Disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableTelemetry" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableDefaultBrowserAgent" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWORD -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name TurnOffSwitch -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name DisableFeedbackDialog -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name DisableEmailInput -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name DisableScreenshotCapture -Type DWORD -Value 1 -Force
Stop-Service "VSStandardCollectorService150"
net stop "VSStandardCollectorService150"
Set-Service  "VSStandardCollectorService150" -StartupType Disabled
#General Optmizations
#Delete "windows.old" folder
%SystemRoot%\System32\Cmd.exe /c Cleanmgr /sageset:65535 
%SystemRoot%\System32\Cmd.exe /c Cleanmgr /sagerun:65535

#Display full path in explorer
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name FullPath -Type DWORD -Value 1 -Force

taskkill -Force /im explorer.exe
Start-Process explorer.exe

#Make icons easier to touch in exploere
:: Needs: Windows 10 build 19592+

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name FileExplorerInTouchImprovement -Type DWORD -Value 1 -Force

:: To kill and restart explorer
taskkill -Force /im explorer.exe
Start-Process explorer.exe
#disable
### Disable app access to account info
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name Value -Type String -Value Deny -Force
### Disable app access to calendar
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name Value -Type String -Value Deny -Force
### Disable app access to call history
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name Value -Type String -Value Deny -Force
### Disable app access to contacts
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name Value -Type String -Value Deny -Force
### Disable app access to diagnostic information
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name Value -Type String -Value Deny -Force
### Disable app access to documents
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name Value -Type String -Value Deny -Force
### Disable app access to email
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name Value -Type String -Value Deny -Force
### Disable app access to file system
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name Value -Type String -Value Deny -Force
### Disable app access to location
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name Value -Type String -Value Deny -Force
### Disable app access to messaging
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name Value -Type String -Value Deny -Force
### Disable app access to motion
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name Value -Type String -Value Deny -Force
### Disable app access to notifications
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Type String -Name Value -Value Deny -Force
### Disable app access to other devices
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" -Name Value -Type String -Value Deny -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name Value -Type String -Value Deny -Force
### Disable app access to call
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" -Name Value -Type String -Value Deny -Force
### Disable app access to pictures
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name Value -Type String -Value Deny -Force
### Disable app access to radios
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name Value -Type String -Value Deny -Force
### Disable app access to tasks
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name Value -Type String -Value Deny -Force
### Disable app access to videos
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name Value -Type String -Value Deny -Force
### Disable tracking of app starts ###
### Windows can personalize your Start menu based on the apps that you launch. ###
### This allows you to quickly have access to your list of Most used apps both in the Start menu and when you search your device.
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Start_TrackProgs -Type DWord -Value 0 -Force
### Disable Bing in Windows Search ### 
### Like Google, Bing is a search engine that needs your data to improve its search results. Windows 10, by default, sends everything you search for in the Start Menu to their servers to give you results from Bing search. ###
### These searches are then uploaded to Microsoft's Privacy Dashboard.
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "BingSearchEnabled" -Type DWord -Value 0 -Force
### Disable Cortana ###
### With the Anniversary Update, Microsoft hid the option to disable Cortana. This policy makes it possible again. It will block the outbound network connections completely in the Firewall.
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0 -Force
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules")) {
	New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" -Type String -Value "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search and Cortana application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" -Force

 
### Prevent Edge from running in background ###
### On the new Chromium version of Microsoft Edge, extensions and other services can keep the browser running in the background even after it's closed. ###
### Although this may not be an issue for most desktop PCs, it could be a problem for laptops and low-end devices as these background processes can increase battery consumption and memory usage. The background process displays an icon in the system tray and can always be closed from there. ###
### If you run enable this policy the background mode will be disabled.
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Type DWord -Value 0 -Force

### Disable synchronization of data ###
### This policy will disable synchronization of data using Microsoft sync services.
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SyncDisabled" -Type DWord -Value 1 -Force

### Disable AutoFill for credit cards ###
### Microsoft Edge's AutoFill feature lets users auto complete credit card information in web forms using previously stored information. ### 
### If you enable this policy, Autofill never suggests or fills credit card information, nor will it save additional credit card information that users might submit while browsing the web.
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AutofillCreditCardEnabled" -Type DWord -Value 0 -Force

### Disable Game Bar features ###
### The Game DVR is a feature of the Xbox app that lets you use the Game bar (Win+G) to record and share game clips and screenshots in Windows 10. However, you can also use the Game bar to record videos and take screenshots of any app in Windows 10. ###
### This Policy will disable the Windows Game Recording and Broadcasting.
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0 -Force
### Block suggestions and automatic Installation of apps ###
### Microsoft flushes various apps into the system without being asked, especially games such as Candy Crush Saga. Users have to uninstall these manually if they don't want them on their computer. ###
### To prevent these downloads from starting in the first place, a small intervention in the registry helps. Suggested apps pinned to Start are basically just advertising. This script will also disable suggested apps (ex: Candy Crush Soda Saga) for all accounts.
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 -Force
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 -Force

### Disable Clipboard history ### 
### With Windows 10 build 17666 or later, Microsoft has allowed cloud synchronization of clipboard. It is a special feature to sync clipboard content across all your devices connected with your Microsoft Account.
New-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 0 -Force
### Disable Compatibility Telemetry ###
### The Windows Compatibility Telemetry process is periodically collecting a variety of technical data about your computer and its performance and sending it to Microsoft for its Windows Customer Experience Improvement Program. It is enabled by default, and the data points are useful for Microsoft to improve Windows 10. ###
### The CompatTelRunner.exe file is also used to upgrade your system to the latest OS version and install the latest updates. ###
### The process is not generally required for the Windows operating system to run properly and can be stopped or deleted. This script will disable the CompatTelRunner.exe (Compatibility Telemetry process) in a more cleaner way using Image File Execution Options Debugger Value. Setting this value to an executable designed to kill processes disables it. Windows won't re-enable it with almost each update. 
If (!(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe")) {
	New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type String -Value "%windir%\System32\taskkill.exe" -Force

 
### Disable Customer Experience Improvement Program ###
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask
### Disable Location tracking ###
### When Location Tracking is turned on, Windows and its apps are allowed to detect the current location of your computer or device. ###
### This can be used to pinpoint your exact location, e.g. Map traces the location of PC and helps you in exploring nearby restaurants.
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny" -Force
### Disable telemetry in Windows 10 ###
### As you use Windows 10, Microsoft will collect usage information. All its options are available in Settings -> Privacy - Feedback and Diagnostics. There you can set the options "Diagnostic and usage data" to Basic, Enhanced and Full. This will set diagnostic data to Basic, which is the lowest level available for all consumer versions of Windows 10 ###
### NOTE: Diagnostic Data must be set to Full to get preview builds from Windows-Insider-Program! Just set the value of the AllowTelemetry key to "3" to revert the policy changes. All other changes remain unaffected.
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\" -Name "DataCollection" -Type DWord -Value 0 -Force
# Stop and Disable Diagnostic Tracking Service
New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type DWord -Value 4 -Force
Stop-Service -Name DiagTrack
Set-Service -Name DiagTrack -StartupType Disabled
# Stop and Disable dmwappushservice Service
New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushsvc" -Name "Start" -Type DWord -Value 4 -Force
Stop-Service -Name dmwappushservice
Set-Service -Name dmwappushservice -StartupType Disabled
### Disable Timeline history ### 
### Microsoft made Timeline available to the public with Windows 10 build 17063. It collects a history of activities you've performed, including files you've opened and web pages you've viewed in Edge.
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0 -Force
### Disable Wi-Fi Sense ### 
### Wi-Fi Sense is a feature in Windows 10 that allows you to connect to your friends shared Wi-Fi connections. That is, you and your friends may opt to share your or their Wi-Fi connections. If your computer is logged into a Microsoft account, by default it will share your Wi-Fi password with your Skype, Outlook and Facebook friends, which means your Wi-Fi password will be sent to Microsoft. ###
### You should at least stop your PC from sending your Wi-Fi password.
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0 -Force
### Disable Windows Tips ###
### Microsoft uses diagnostic information to determine which tips are appropriate. If you enable this policy, you will no longer see Windows Tips, e.g. Spotlight and Consumer Features, Feedback Notifications etc.
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Type DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeature" -Type DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1 -Force

### Do not show feedback notifications ### 
### Windows 10 doesn’t just automatically collect information about your computer usage. It does do that, but it may also pop up from time to time and ask for feedback. This information is used to improve Windows 10 - in theory. As of Windows 10’s “November Update,” the Windows Feedback application is installed by default on all Windows 10 PCs. ###
### If you are running Windows 10 in a corporate setting, you should likely disable the Windows Feedback prompts that appear every few weeks.
New-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0 -Force
### Prevent using diagnostic data ### 
### Starting with Windows 10 build 15019, a new privacy setting to "let Microsoft provide more tailored experiences with relevant tips and recommendations by using your diagnostic data" has been added. By enabling this policy you can prevent Microsoft from using your diagnostic data. 
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 0 -Force
### Turn off Advertising ID for Relevant Ads ###
### Windows 10 comes integrated with advertising. Microsoft assigns a unique identificator to track your activity in the Microsoft Store and on UWP apps to target you with relevant ads. ###
### If someone is giving you personalized ads, it means they are tracking your data. Turn off the advertising feature from Windows 10 with this policy to stay secure.
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0 -Force
### Turn off help Microsoft improve typing and writing ### 
### When the Getting to know you privacy setting is turned on for inking & typing personalization in Windows 10, you can use your typing history and handwriting patterns to create a local user dictionary for you that is used to make better typing suggestions and improve handwriting recognition for each of the languages you use.
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1 -Force
### Disable password reveal button ###
### On the new login screen, Microsoft added a password review button that displays what's in the password box in plain text when pressed. Note that, disabling Password Reveal button disables this feature not only in login screen but also in Microsoft Edge, Internet Explorer as well. ###
### Visible passwords may be seen by nearby persons, compromising them. The password reveal button can be used to display an entered password and should be disabled with this policy.
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Type DWord -Value 1 -Force

### Disable Windows Media DRM Internet Access ###
### DRM stands for digital rights management. DRM is a technology used by content providers, such as online stores, to control how the digital music and video files you obtain from them are used and distributed. Online stores sell and rent songs and movies that have DRM applied to them. ###
### If the Windows Media Digital Rights Management should not get access to the Internet, you can enable this policy to prevent it.
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\WMDRM")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWord -Value 1 -Force

### Disable forced updates ###
### This will notify when updates are available, and you decide when to install them.
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Type DWord -Value 3 -Force

### Turn off distributing updates to other computers ###
### Windows 10 lets you download updates from several sources to speed up the process of updating the operating system. ###
### If you don't want your files to be shared by others and exposing your IP address to random computers, you can apply this policy and turn this feature off. ### 
### Acceptable selections include:
### Bypass (100) 
### Group (2)
### HTTP only (0) Enabled by SharpApp!
### LAN (1)
### Simple (99)
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 0 -Force

### Disable Windows Error Reporting ### 
### The error reporting feature in Windows is what produces those alerts after certain program or operating system errors, prompting you to send the information about the problem to Microsoft.
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1 -Force
Get-ScheduledTask -TaskName "QueueReporting" | Disable-ScheduledTask
#Opt-out nVidia telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID44231 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID64640 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name EnableRID66610 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" -Name OptInOrOutPreference -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" -Name Start -Type DWORD -Value 4 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\Startup\SendTelemetryData" -Name 0 -Type DWORD -Value 0 -Force
Stop-Service NvTelemetryContainer
Set-Service NvTelemetryContainer -StartupType Disabled
schtasks /change /TN NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /Disable
schtasks /change /TN NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /Disable
schtasks /change /TN NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /Disable
schtasks /change /TN NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /Disable

#Disable Razer Game Scanner service
Stop-Service "Razer Game Scanner Service"
Set-Service "Razer Game Scanner Service" -StartupType Disabled

#Disable Game Bar features
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name AllowgameDVR -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type DWORD -Value 0 -Force

#Disable Logitech Gaming service
Stop-Service "LogiRegistryService"
Set-Service "LogiRegistryService" -StartupType Disabled

#Disable Visual Studio telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM" -Name OptIn -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWORD -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name TurnOffSwitch -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name DisableFeedbackDialog -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name DisableEmailInput -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name DisableScreenshotCapture -Type DWORD -Value 1 -Force
Stop-Service "VSStandardCollectorService150"
Run net stop "VSStandardCollectorService150"
Set-Service "VSStandardCollectorService150" -StartupType Disabled

#Block Google Chrome Software Reporter Tool
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name Debugger -Type STRING -Value "%windir%\System32\taskkill.exe" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type STRING -Value 0 -Force

#Disable storing sensitive data in Acrobat Reader DC
Set-ItemProperty -Path "HKCU:\Software\Adobe\Adobe ARM\1.0\ARM" -Name "iCheck" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "cSharePoint" -Type STRING -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeDocumentServices" -Type STRING -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeSign" -Type STRING -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bTogglePrefSync" -Type STRING -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleWebConnectors" -Type STRING -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bAdobeSendPluginToggle" -Type STRING -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bUpdater" -Type STRING -Value 0 -Force

#Disable CCleaner Health Check
Stop-Process -Force -Name  ccleaner.exe
Stop-Process -Force -Name  ccleaner64.exe
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HomeScreen" -Type STRING -Value 2 -Force

#Disable CCleaner Monitoring && more
Stop-Process -Force -Name "IMAGENAME eq CCleaner*"
schtasks /Change /TN "CCleaner Update" /Disable
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "Monitoring" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HelpImproveCCleaner" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "SystemMonitoring" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "SystemMonitoringRunningNotification" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateAuto" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateCheck" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "CheckTrialOffer" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)GetIpmForTrial" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdater" -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdaterIpm" -Type STRING -Value 0 -Force

#Disable Dropbox Update service
Set-Service dbupdate -StartupType Disabled
Set-Service dbupdatem -StartupType Disabled
schtasks /Change /TN "DropboxUpdateTaskMachineCore" /Disable
schtasks /Change /TN "DropboxUpdateTaskMachineUA" /Disable

#Disable Google update service
schtasks /Change /TN "GoogleUpdateTaskMachineCore" /Disable
schtasks /Change /TN "GoogleUpdateTaskMachineUA" /Disable

#Disable Media Player telemetry
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWORD -Value 1 -Force
Set-Service WMPNetworkSvc -StartupType Disabled

#Disable Microsoft Office telemetry
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name "Enablelogging" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name "EnableUpload" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Type DWORD -Value 0 -Force

#Disable Microsoft Windows Live ID service
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\wlidsvc" -Name Start -Type DWORD -Value 4 -Force
Set-Service wlidsvc -StartupType Disabled

#Disable Mozilla Firefox telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableTelemetry" -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableDefaultBrowserAgent" -Type DWORD -Value 1 -Force

#Remove Windows Bloatware
Get-AppxPackage -allusers *xing* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.XboxApp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.GamingApp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.BingWeather* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft3DViewer* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Twitter* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Getstarted* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Office.Sway* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *spotify* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *bingsports* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.SkypeApp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *WindowsScan* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Print3D* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *CommsPhone* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Messaging* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *empires* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *microsoft.windowscommunicationsapps* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.ZuneMusic* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsMaps* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.3dbuilder* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft3DViewer* |  Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *AdobeSystemsIncorporated.AdobePhotoshopExpress* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsAlarms* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Appconnector* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.YourPhone* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Asphalt8Airborne* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *candycrush* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *DolbyLaboratories.DolbyAccess* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.DrawboardPDF* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Facebook* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *FarmHeroesSaga* | Remove-AppxPackage 
Get-AppxPackage -allusers *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.XboxGamingOverlay* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.GetHelp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.BingNews* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Todos* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Whiteboard* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *ConnectivityStore* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *MinecraftUWP* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MixedReality.Portal* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.OneConnect* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.ZuneVideo* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Netflix* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *OneNote* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MSPaint* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *PandoraMediaInc* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *CommsPhone* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *windowsphone* | Remove-AppxPackage -AllUsers

#   Description:
# This script blocks telemetry related domains via the hosts file and related
# IPs via Windows Firewall.
#
# Please note that adding these domains may break certain software like iTunes
# or Skype. As this issue is location dependent for some domains, they are not
# commented by default. The domains known to cause issues marked accordingly.
# Please see the related issue:
# <https://github.com/W4RH4WK/Debloat-Windows-10/issues/79>

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\force-mkdir.psm1

Write-Output "Disabling telemetry via Group Policies"
force-mkdir "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0

# Entries related to Akamai have been reported to cause issues with Widevine
# DRM.

Write-Output "Adding telemetry domains to hosts file"
$hosts_file = "$env:systemroot\System32\drivers\etc\hosts"
$domains = @(
    "184-86-53-99.deploy.static.akamaitechnologies.com"
    "a-0001.a-msedge.net"
    "a-0002.a-msedge.net"
    "a-0003.a-msedge.net"
    "a-0004.a-msedge.net"
    "a-0005.a-msedge.net"
    "a-0006.a-msedge.net"
    "a-0007.a-msedge.net"
    "a-0008.a-msedge.net"
    "a-0009.a-msedge.net"
    "a1621.g.akamai.net"
    "a1856.g2.akamai.net"
    "a1961.g.akamai.net"
    #"a248.e.akamai.net"            # makes iTunes download button disappear (#43)
    "a978.i6g1.akamai.net"
    "a.ads1.msn.com"
    "a.ads2.msads.net"
    "a.ads2.msn.com"
    "ac3.msn.com"
    "ad.doubleclick.net"
    "adnexus.net"
    "adnxs.com"
    "ads1.msads.net"
    "ads1.msn.com"
    "ads.msn.com"
    "aidps.atdmt.com"
    "aka-cdn-ns.adtech.de"
    "a-msedge.net"
    "any.edge.bing.com"
    "a.rad.msn.com"
    "az361816.vo.msecnd.net"
    "az512334.vo.msecnd.net"
    "b.ads1.msn.com"
    "b.ads2.msads.net"
    "bingads.microsoft.com"
    "b.rad.msn.com"
    "bs.serving-sys.com"
    "c.atdmt.com"
    "cdn.atdmt.com"
    "cds26.ams9.msecn.net"
    "choice.microsoft.com"
    "choice.microsoft.com.nsatc.net"
    "compatexchange.cloudapp.net"
    "corpext.msitadfs.glbdns2.microsoft.com"
    "corp.sts.microsoft.com"
    "cs1.wpc.v0cdn.net"
    "db3aqu.atdmt.com"
    "df.telemetry.microsoft.com"
    "diagnostics.support.microsoft.com"
    "e2835.dspb.akamaiedge.net"
    "e7341.g.akamaiedge.net"
    "e7502.ce.akamaiedge.net"
    "e8218.ce.akamaiedge.net"
    "ec.atdmt.com"
    "fe2.update.microsoft.com.akadns.net"
    "feedback.microsoft-hohm.com"
    "feedback.search.microsoft.com"
    "feedback.windows.com"
    "flex.msn.com"
    "g.msn.com"
    "h1.msn.com"
    "h2.msn.com"
    "hostedocsp.globalsign.com"
    "i1.services.social.microsoft.com"
    "i1.services.social.microsoft.com.nsatc.net"
    "ipv6.msftncsi.com"
    "ipv6.msftncsi.com.edgesuite.net"
    "lb1.www.ms.akadns.net"
    "live.rads.msn.com"
    "m.adnxs.com"
    "msedge.net"
    "msftncsi.com"
    "msnbot-65-55-108-23.search.msn.com"
    "msntest.serving-sys.com"
    "oca.telemetry.microsoft.com"
    "oca.telemetry.microsoft.com.nsatc.net"
    "onesettings-db5.metron.live.nsatc.net"
    "pre.footprintpredict.com"
    "preview.msn.com"
    "rad.live.com"
    "rad.msn.com"
    "redir.metaservices.microsoft.com"
    "reports.wes.df.telemetry.microsoft.com"
    "schemas.microsoft.akadns.net"
    "secure.adnxs.com"
    "secure.flashtalking.com"
    "services.wes.df.telemetry.microsoft.com"
    "settings-sandbox.data.microsoft.com"
    #"settings-win.data.microsoft.com"       # may cause issues with Windows Updates
    "sls.update.microsoft.com.akadns.net"
    #"sls.update.microsoft.com.nsatc.net"    # may cause issues with Windows Updates
    "sqm.df.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com.nsatc.net"
    "ssw.live.com"
    "static.2mdn.net"
    "statsfe1.ws.microsoft.com"
    "statsfe2.update.microsoft.com.akadns.net"
    "statsfe2.ws.microsoft.com"
    "survey.watson.microsoft.com"
    "telecommand.telemetry.microsoft.com"
    "telecommand.telemetry.microsoft.com.nsatc.net"
    "telemetry.appex.bing.net"
    "telemetry.microsoft.com"
    "telemetry.urs.microsoft.com"
    "vortex-bn2.metron.live.com.nsatc.net"
    "vortex-cy2.metron.live.com.nsatc.net"
    "vortex.data.microsoft.com"
    "vortex-sandbox.data.microsoft.com"
    "vortex-win.data.microsoft.com"
    "cy2.vortex.data.microsoft.com.akadns.net"
    "watson.live.com"
    "watson.microsoft.com"
    "watson.ppe.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com.nsatc.net"
    "wes.df.telemetry.microsoft.com"
    "win10.ipv6.microsoft.com"
    "www.bingads.microsoft.com"
    "www.go.microsoft.akadns.net"
    "www.msftncsi.com"
    "client.wns.windows.com"
    #"wdcp.microsoft.com"                       # may cause issues with Windows Defender Cloud-based protection
    #"dns.msftncsi.com"                         # This causes Windows to think it doesn't have internet
    #"storeedgefd.dsx.mp.microsoft.com"         # breaks Windows Store
    "wdcpalt.microsoft.com"
    "settings-ssl.xboxlive.com"
    "settings-ssl.xboxlive.com-c.edgekey.net"
    "settings-ssl.xboxlive.com-c.edgekey.net.globalredir.akadns.net"
    "e87.dspb.akamaidege.net"
    "insiderservice.microsoft.com"
    "insiderservice.trafficmanager.net"
    "e3843.g.akamaiedge.net"
    "flightingserviceweurope.cloudapp.net"
    #"sls.update.microsoft.com"                 # may cause issues with Windows Updates
    "static.ads-twitter.com"                    # may cause issues with Twitter login
    "www-google-analytics.l.google.com"
    "p.static.ads-twitter.com"                  # may cause issues with Twitter login
    "hubspot.net.edge.net"
    "e9483.a.akamaiedge.net"

    #"www.google-analytics.com"
    #"padgead2.googlesyndication.com"
    #"mirror1.malwaredomains.com"
    #"mirror.cedia.org.ec"
    "stats.g.doubleclick.net"
    "stats.l.doubleclick.net"
    "adservice.google.de"
    "adservice.google.com"
    "googleads.g.doubleclick.net"
    "pagead46.l.doubleclick.net"
    "hubspot.net.edgekey.net"
    "insiderppe.cloudapp.net"                   # Feedback-Hub
    "livetileedge.dsx.mp.microsoft.com"

    # extra
    "fe2.update.microsoft.com.akadns.net"
    "s0.2mdn.net"
    "statsfe2.update.microsoft.com.akadns.net"
    "survey.watson.microsoft.com"
    "view.atdmt.com"
    "watson.microsoft.com"
    "watson.ppe.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com.nsatc.net"
    "wes.df.telemetry.microsoft.com"
    "m.hotmail.com"

    # can cause issues with Skype (#79) or other services (#171)
    "apps.skype.com"
    "c.msn.com"
    # "login.live.com"                  # prevents login to outlook and other live apps
    "pricelist.skype.com"
    "s.gateway.messenger.live.com"
    "ui.skype.com"
)
Write-Output "" | Out-File -Encoding ASCII -Append $hosts_file
foreach ($domain in $domains) {
    if (-Not (Select-String -Path $hosts_file -Pattern $domain)) {
        Write-Output "0.0.0.0 $domain" | Out-File -Encoding ASCII -Append $hosts_file
    }
}

Write-Output "Adding telemetry ips to firewall"
$ips = @(
    "134.170.30.202"
    "137.116.81.24"
    "157.56.106.189"
    "184.86.53.99"
    "2.22.61.43"
    "2.22.61.66"
    "204.79.197.200"
    "23.218.212.69"
    "65.39.117.230"
    "65.52.108.33"   # Causes problems with Microsoft Store
    "65.55.108.23"
    "64.4.54.254"
)
Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound `
    -Action Block -RemoteAddress ([string[]]$ips)

#   Description:
# This script will try to fix many of the privacy settings for the user. This
# is work in progress!

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\force-mkdir.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Defuse Windows search settings"
Set-WindowsSearchSetting -EnableWebResultsSetting $false

Write-Output "Set general privacy options"
# "Let websites provide locally relevant content by accessing my language list"
Set-ItemProperty "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1
# Locaton aware printing (changes default based on connected network)
force-mkdir "HKCU:\Printers\Defaults"
Set-ItemProperty "HKCU:\Printers\Defaults" "NetID" "{00000000-0000-0000-0000-000000000000}"
# "Send Microsoft info about how I write to help us improve typing and writing in the future"
force-mkdir "HKCU:\SOFTWARE\Microsoft\Input\TIPC"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Input\TIPC" "Enabled" 0
# "Let apps use my advertising ID for experiencess across apps"
force-mkdir "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
# "Turn on SmartScreen Filter to check web content"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0

Write-Output "Disable synchronisation of settings"
# These only apply if you log on using Microsoft account
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "BackupPolicy" 0x3c
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "DeviceMetadataUploaded" 0
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "PriorLogons" 1
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
    force-mkdir "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group"
    Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group" "Enabled" 0
}

Write-Output "Set privacy policy accepted state to 0"
# Prevents sending speech, inking and typing samples to MS (so Cortana
# can learn to recognise you)
force-mkdir "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0

Write-Output "Do not scan contact informations"
# Prevents sending contacts to MS (so Cortana can compare speech etc samples)
force-mkdir "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0

Write-Output "Inking and typing settings"
# Handwriting recognition personalization
force-mkdir "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1

Write-Output "Microsoft Edge settings"
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main"
Set-ItemProperty "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" "DoNotTrack" 1
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes"
Set-ItemProperty "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" "ShowSearchSuggestionsGlobal" 0
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead"
Set-ItemProperty "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" "FPEnabled" 0
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
Set-ItemProperty "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" "EnabledV9" 0

Write-Output "Disable background access of default apps"
foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
    Set-ItemProperty ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + $key.PSChildName) "Disabled" 1
}

Write-Output "Denying device access"
# Disable sharing information with unpaired devices
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Type" "LooselyCoupled"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Value" "Deny"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "InitialAppValue" "Unspecified"
foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global")) {
    if ($key.PSChildName -EQ "LooselyCoupled") {
        continue
    }
    Set-ItemProperty ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "Type" "InterfaceClass"
    Set-ItemProperty ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "Value" "Deny"
    Set-ItemProperty ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "InitialAppValue" "Unspecified"
}

Write-Output "Disable location sensor"
force-mkdir "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0

Write-Output "Disable submission of Windows Defender findings (w/ elevated privileges)"
Takeown-Registry("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet")
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SpyNetReporting" 0       # write-protected even after takeown ?!
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent" 0

Write-Output "Do not share wifi networks"
$user = New-Object System.Security.Principal.NTAccount($env:UserName)
$sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).value
force-mkdir ("HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid)
Set-ItemProperty ("HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid) "FeatureStates" 0x33c
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseCredShared" 0
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseOpen" 0

#   Description:
# This script removes unwanted Apps that come with Windows. If you  do not want
# to remove certain Apps comment out the corresponding lines below.

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\force-mkdir.psm1

Write-Output "Elevating privileges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Uninstalling default apps"
$apps = @(
    # default Windows 10 apps
    "Microsoft.3DBuilder"
    "Microsoft.Appconnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    #"Microsoft.FreshPaint"
    "Microsoft.GamingServices"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftPowerBIForWindows"
    "Microsoft.MicrosoftSolitaireCollection"
    #"Microsoft.MicrosoftStickyNotes"
    "Microsoft.MinecraftUWP"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.Office.OneNote"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    #"Microsoft.Windows.Photos"
    "Microsoft.WindowsAlarms"
    #"Microsoft.WindowsCalculator"
    "Microsoft.WindowsCamera"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsSoundRecorder"
    #"Microsoft.WindowsStore"   # can't be re-installed
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    #"Microsoft.XboxGameOverlay"
    #"Microsoft.XboxGamingOverlay"
    #"Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"

    # Threshold 2 apps
    "Microsoft.CommsPhone"
    "Microsoft.ConnectivityStore"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.WindowsFeedbackHub"

    # Creators Update apps
    "Microsoft.Microsoft3DViewer"
    #"Microsoft.MSPaint"

    #Redstone apps
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingTravel"
    "Microsoft.WindowsReadingList"

    # Redstone 5 apps
    "Microsoft.MixedReality.Portal"
    "Microsoft.ScreenSketch"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.YourPhone"

    # non-Microsoft
    "2FE3CB00.PicsArt-PhotoStudio"
    "46928bounde.EclipseManager"
    "4DF9E0F8.Netflix"
    "613EBCEA.PolarrPhotoEditorAcademicEdition"
    "6Wunderkinder.Wunderlist"
    "7EE7776C.LinkedInforWindows"
    "89006A2E.AutodeskSketchBook"
    "9E2F88E3.Twitter"
    "A278AB0D.DisneyMagicKingdoms"
    "A278AB0D.MarchofEmpires"
    "ActiproSoftwareLLC.562882FEEB491" # next one is for the Code Writer from Actipro Software LLC
    "CAF9E577.Plex"  
    "ClearChannelRadioDigital.iHeartRadio"
    "D52A8D61.FarmVille2CountryEscape"
    "D5EA27B7.Duolingo-LearnLanguagesforFree"
    "DB6EA5DB.CyberLinkMediaSuiteEssentials"
    "DolbyLaboratories.DolbyAccess"
    "DolbyLaboratories.DolbyAccess"
    "Drawboard.DrawboardPDF"
    "Facebook.Facebook"
    "Fitbit.FitbitCoach"
    "Flipboard.Flipboard"
    "GAMELOFTSA.Asphalt8Airborne"
    "KeeperSecurityInc.Keeper"
    "NORDCURRENT.COOKINGFEVER"
    "PandoraMediaInc.29680B314EFC2"
    "Playtika.CaesarsSlotsFreeCasino"
    "ShazamEntertainmentLtd.Shazam"
    "SlingTVLLC.SlingTV"
    "SpotifyAB.SpotifyMusic"
    #"TheNewYorkTimes.NYTCrossword"
    "ThumbmunkeysLtd.PhototasticCollage"
    "TuneIn.TuneInRadio"
    "WinZipComputing.WinZipUniversal"
    "XINGAG.XING"
    "flaregamesGmbH.RoyalRevolt2"
    "king.com.*"
    "king.com.BubbleWitch3Saga"
    "king.com.CandyCrushSaga"
    "king.com.CandyCrushSodaSaga"

    # apps which cannot be removed using Remove-AppxPackage
    #"Microsoft.BioEnrollment"
    #"Microsoft.MicrosoftEdge"
    #"Microsoft.Windows.Cortana"
    #"Microsoft.WindowsFeedback"
    #"Microsoft.XboxGameCallableUI"
    #"Microsoft.XboxIdentityProvider"
    #"Windows.ContactSupport"

    # apps which other apps depend on
    "Microsoft.Advertising.Xaml"
)

foreach ($app in $apps) {
    Write-Output "Trying to remove $app"

    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers

    Get-AppXProvisionedPackage -Online |
        Where-Object DisplayName -EQ $app |
        Remove-AppxProvisionedPackage -Online
}

# Prevents Apps from re-installing
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

force-mkdir "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach ($key in $cdm) {
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
}

force-mkdir "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2

# Prevents "Suggested Applications" returning
force-mkdir "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1


#   Description:
# This script will remove and disable OneDrive integration.

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\force-mkdir.psm1
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
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Output "Disable OneDrive via Group Policies"
force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

# Thank you Matthew Israelsson
Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
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


#GPO Configurations
.\Files\LGPO\LGPO.exe /g .\Files\GPOs\
