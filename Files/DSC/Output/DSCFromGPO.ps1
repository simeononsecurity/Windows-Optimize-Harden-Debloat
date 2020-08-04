
Configuration DSCFromGPO
{

	Import-DSCResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
	# Module Not Found: Import-DSCResource -ModuleName 'PowerShellAccessControl'
	Node localhost
	{
         Registry 'Registry(POL): HKLM:\software\microsoft\OneDrive\Remote Access\GPOEnabled'
         {
              ValueName = 'GPOEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\OneDrive\Remote Access'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\Microsoft\OneDrive\Remote Access\GPOEnabled'
         {
              ValueName = 'GPOEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\Microsoft\OneDrive\Remote Access'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\infopath\security\aptca_allowlist'
         {
              ValueName = 'aptca_allowlist'
              ValueType = 'Dword'
              Key = 'HKLM:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Appx\EnforcementMode'
         {
              ValueName = 'EnforcementMode'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Appx'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Appx\a9e18c21-ff8f-43cf-b9fc-db40eed693ba\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Appx\a9e18c21-ff8f-43cf-b9fc-db40eed693ba'
              ValueData = '<FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\EnforcementMode'
         {
              ValueName = 'EnforcementMode'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\1d04fdc7-5e29-45b1-a0d7-f7e9293774f8\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\1d04fdc7-5e29-45b1-a0d7-f7e9293774f8'
              ValueData = '<FilePathRule Id="1d04fdc7-5e29-45b1-a0d7-f7e9293774f8" Name="Allows administrators to execute all DLLs" Description="Allows members of the local Administrators group to load all DLLs." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\7ca2deae-991c-4e26-b688-98137f9cc777\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\7ca2deae-991c-4e26-b688-98137f9cc777'
              ValueData = '<FilePathRule Id="7ca2deae-991c-4e26-b688-98137f9cc777" Name="Allow everyone to execute all DLLs located in the Windows folder" Description="Allows members of the Everyone group to load DLLs located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions><Exceptions><FilePathCondition Path="%SYSTEM32%\catroot2\*"/><FilePathCondition Path="%SYSTEM32%\com\dmp\*"/><FilePathCondition Path="%SYSTEM32%\FxsTmp\*"/><FilePathCondition Path="%SYSTEM32%\spool\drivers\color\*"/><FilePathCondition Path="%SYSTEM32%\spool\PRINTERS\*"/><FilePathCondition Path="%SYSTEM32%\spool\SERVERS\*"/><FilePathCondition Path="%SYSTEM32%\Tasks\*"/><FilePathCondition Path="%WINDIR%\Debug\*"/><FilePathCondition Path="%WINDIR%\PCHEALTH\ERRORREP\*"/><FilePathCondition Path="%WINDIR%\Registration\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\*"/><FilePathCondition Path="%WINDIR%\Tasks\*"/><FilePathCondition Path="%WINDIR%\Temp\*"/><FilePathCondition Path="%WINDIR%\tracing\*"/></Exceptions></FilePathRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\f36fbeba-ab50-48c0-9361-41af365d82ce\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\f36fbeba-ab50-48c0-9361-41af365d82ce'
              ValueData = '<FilePathRule Id="f36fbeba-ab50-48c0-9361-41af365d82ce" Name="Allow everyone to execute all DLLs located in the Program Files folder" Description="Allows members of the Everyone group to load DLLs that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\EnforcementMode'
         {
              ValueName = 'EnforcementMode'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\1712f2de-e1b6-4d3d-85a9-a7da49b796c1\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\1712f2de-e1b6-4d3d-85a9-a7da49b796c1'
              ValueData = '<FilePathRule Id="1712f2de-e1b6-4d3d-85a9-a7da49b796c1" Name="Allow everyone to execute all files located in the Program Files folder" Description="Allows members of the Everyone group to run applications that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\187ae870-255e-42d7-8ef9-9a8434a70716\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\187ae870-255e-42d7-8ef9-9a8434a70716'
              ValueData = '<FilePublisherRule Id="187ae870-255e-42d7-8ef9-9a8434a70716" Name="Prevent administrators from easily running the Internet Explorer web browser" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="WINDOWS® INTERNET EXPLORER" BinaryName="IEXPLORE.EXE"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\230ebde7-123f-4f56-9caf-a412e5265300\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\230ebde7-123f-4f56-9caf-a412e5265300'
              ValueData = '<FilePublisherRule Id="230ebde7-123f-4f56-9caf-a412e5265300" Name="Prevent administrators from easily running the Outlook email client" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT OFFICE OUTLOOK" BinaryName="OUTLOOK.EXE"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\54d44e7f-44b7-4d8d-961e-6d9c47e03196\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\54d44e7f-44b7-4d8d-961e-6d9c47e03196'
              ValueData = '<FilePublisherRule Id="54d44e7f-44b7-4d8d-961e-6d9c47e03196" Name="Prevent administrators from easily running the Thunderbird email client" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MOZILLA MESSAGING INC., L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" ProductName="THUNDERBIRD" BinaryName="thunderbird.exe"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\97bca7b1-6ff4-40a5-a1fe-e8e8535f6e1e\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\97bca7b1-6ff4-40a5-a1fe-e8e8535f6e1e'
              ValueData = '<FilePublisherRule Id="97bca7b1-6ff4-40a5-a1fe-e8e8535f6e1e" Name="Prevent administrators from easily running the Chrome web browser" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=GOOGLE INC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" ProductName="GOOGLE CHROME" BinaryName="chrome.exe"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\980f805b-bc66-43c7-95c4-90ef50fe5b04\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\980f805b-bc66-43c7-95c4-90ef50fe5b04'
              ValueData = '<FilePublisherRule Id="980f805b-bc66-43c7-95c4-90ef50fe5b04" Name="Prevent administrators from easily running the Firefox web browser" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MOZILLA CORPORATION, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" ProductName="FIREFOX" BinaryName="firefox.exe"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\a88c9192-bbed-4dfe-b435-d0ca25f6576e\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\a88c9192-bbed-4dfe-b435-d0ca25f6576e'
              ValueData = '<FilePublisherRule Id="a88c9192-bbed-4dfe-b435-d0ca25f6576e" Name="Prevent administrators from easily running the Opera web browser" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=OPERA SOFTWARE ASA, S=OSLO, C=NO" ProductName="OPERA" BinaryName="opera.exe"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\afd4074c-4b47-4b55-bb6d-f35ea215408b\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\afd4074c-4b47-4b55-bb6d-f35ea215408b'
              ValueData = '<FilePathRule Id="afd4074c-4b47-4b55-bb6d-f35ea215408b" Name="Allow everyone to execute all files located in the Windows folder" Description="Allows members of the Everyone group to run applications that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions><Exceptions><FilePathCondition Path="%SYSTEM32%\catroot2\*"/><FilePathCondition Path="%SYSTEM32%\com\dmp\*"/><FilePathCondition Path="%SYSTEM32%\FxsTmp\*"/><FilePathCondition Path="%SYSTEM32%\spool\drivers\color\*"/><FilePathCondition Path="%SYSTEM32%\spool\PRINTERS\*"/><FilePathCondition Path="%SYSTEM32%\spool\SERVERS\*"/><FilePathCondition Path="%SYSTEM32%\Tasks\*"/><FilePathCondition Path="%WINDIR%\Debug\*"/><FilePathCondition Path="%WINDIR%\PCHEALTH\ERRORREP\*"/><FilePathCondition Path="%WINDIR%\Registration\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\*"/><FilePathCondition Path="%WINDIR%\Tasks\*"/><FilePathCondition Path="%WINDIR%\Temp\*"/><FilePathCondition Path="%WINDIR%\tracing\*"/></Exceptions></FilePathRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\f301f291-10d9-4423-8f9c-a78afe9d4ea5\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\f301f291-10d9-4423-8f9c-a78afe9d4ea5'
              ValueData = '<FilePathRule Id="f301f291-10d9-4423-8f9c-a78afe9d4ea5" Name="Allow administrators to execute all files" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\f53c8fc8-d0dd-43c4-b874-57f31ba6f4aa\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\f53c8fc8-d0dd-43c4-b874-57f31ba6f4aa'
              ValueData = '<FilePublisherRule Id="f53c8fc8-d0dd-43c4-b874-57f31ba6f4aa" Name="Prevent administrators from easily running the Safari web browser" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=APPLE INC., L=CUPERTINO, S=CALIFORNIA, C=US" ProductName="SAFARI" BinaryName="Safari.exe"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi\EnforcementMode'
         {
              ValueName = 'EnforcementMode'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi\0b075828-da4a-41fc-b3b4-9ac83ad18add\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi\0b075828-da4a-41fc-b3b4-9ac83ad18add'
              ValueData = '<FilePathRule Id="0b075828-da4a-41fc-b3b4-9ac83ad18add" Name="Allow everyone to run all Windows Installer files located in the Windows\Installer folder." Description="Allows members of the Everyone group to run all Windows Installer files located in %systemdrive%\Windows\Installer." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\Installer\*"/></Conditions></FilePathRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi\4833728f-cf7e-4797-a847-c979e29b597a\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi\4833728f-cf7e-4797-a847-c979e29b597a'
              ValueData = '<FilePathRule Id="4833728f-cf7e-4797-a847-c979e29b597a" Name="Allow administrators to run all Windows Installer files" Description="Allows members of the local Administrators group to run all Windows Installer files." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\EnforcementMode'
         {
              ValueName = 'EnforcementMode'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\4a4170c6-feb8-44f6-bebf-78a319f197fe\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\4a4170c6-feb8-44f6-bebf-78a319f197fe'
              ValueData = '<FilePathRule Id="4a4170c6-feb8-44f6-bebf-78a319f197fe" Name="Allow everyone to run all scripts located in the Program Files folder" Description="Allows members of the Everyone group to run scripts that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\8f42d1d3-5f29-469d-8f37-6f01f6c3b2f4\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\8f42d1d3-5f29-469d-8f37-6f01f6c3b2f4'
              ValueData = '<FilePathRule Id="8f42d1d3-5f29-469d-8f37-6f01f6c3b2f4" Name="Allow everyone to run all scripts located in the Windows folder" Description="Allows members of the Everyone group to run scripts that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions><Exceptions><FilePathCondition Path="%SYSTEM32%\catroot2\*"/><FilePathCondition Path="%SYSTEM32%\com\dmp\*"/><FilePathCondition Path="%SYSTEM32%\FxsTmp\*"/><FilePathCondition Path="%SYSTEM32%\spool\drivers\color\*"/><FilePathCondition Path="%SYSTEM32%\spool\PRINTERS\*"/><FilePathCondition Path="%SYSTEM32%\spool\SERVERS\*"/><FilePathCondition Path="%SYSTEM32%\Tasks\*"/><FilePathCondition Path="%WINDIR%\Debug\*"/><FilePathCondition Path="%WINDIR%\PCHEALTH\ERRORREP\*"/><FilePathCondition Path="%WINDIR%\Registration\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\*"/><FilePathCondition Path="%WINDIR%\Tasks\*"/><FilePathCondition Path="%WINDIR%\Temp\*"/><FilePathCondition Path="%WINDIR%\tracing\*"/></Exceptions></FilePathRule>
'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\ed97d0cb-15ff-430f-b82c-8d7832957725\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\ed97d0cb-15ff-430f-b82c-8d7832957725'
              ValueData = '<FilePathRule Id="ed97d0cb-15ff-430f-b82c-8d7832957725" Name="All scripts" Description="Allows members of the local Administrators group to run all scripts." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
'

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\publisher\promptforbadfiles'
         {
              ValueName = 'promptforbadfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\publisher'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\publisher\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\publisher\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\publisher\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\publisher\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\publisher\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\publisher\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecuritypublisher'
         {
              ValueName = 'automationsecuritypublisher'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\research\translation\useonline'
         {
              ValueName = 'useonline'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\research\translation'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\options\defaultformat'
         {
              ValueName = 'defaultformat'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\options'
              ValueData = '
'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\options\dontupdatelinks'
         {
              ValueName = 'dontupdatelinks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\options'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 1

         }#>

         Registry 'DEL_CU:\software\policies\microsoft\office\16.0\word\security\wordbypassencryptedmacroscan'
         {
              ValueName = 'wordbypassencryptedmacroscan'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = ''
              Ensure = 'Absent'

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\accessvbom'
         {
              ValueName = 'accessvbom'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2files'
         {
              ValueName = 'word2files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2000files'
         {
              ValueName = 'word2000files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 5

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word60files'
         {
              ValueName = 'word60files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word95files'
         {
              ValueName = 'word95files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 5

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word97files'
         {
              ValueName = 'word97files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 5

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\wordxpfiles'
         {
              ValueName = 'wordxpfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 5

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\enableonload'
         {
              ValueName = 'enableonload'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = 1

         }#>

         Registry 'DEL_CU:\software\policies\microsoft\office\16.0\word\security\filevalidation\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = ''
              Ensure = 'Absent'

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\disableeditfrompv'
         {
              ValueName = 'disableeditfrompv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableintranetcheck'
         {
              ValueName = 'disableintranetcheck'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations\alllocationsdisabled'
         {
              ValueName = 'alllocationsdisabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\disableinfopath2003emailforms'
         {
              ValueName = 'disableinfopath2003emailforms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\deployment\cachemailxsn'
         {
              ValueName = 'cachemailxsn'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\deployment'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\deployment\mailxsnwithxml'
         {
              ValueName = 'mailxsnwithxml'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\deployment'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\editor\offline\cachedmodestatus'
         {
              ValueName = 'cachedmodestatus'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\editor\offline'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\gradualupgraderedirection'
         {
              ValueName = 'gradualupgraderedirection'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\emailformsruncodeandscript'
         {
              ValueName = 'emailformsruncodeandscript'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\emailformsbeaconingui'
         {
              ValueName = 'emailformsbeaconingui'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\enablefulltrustemailforms'
         {
              ValueName = 'enablefulltrustemailforms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\enableinternetemailforms'
         {
              ValueName = 'enableinternetemailforms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\enablerestrictedemailforms'
         {
              ValueName = 'enablerestrictedemailforms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\runfulltrustsolutions'
         {
              ValueName = 'runfulltrustsolutions'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\allowinternetsolutions'
         {
              ValueName = 'allowinternetsolutions'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\infopathbeaconingui'
         {
              ValueName = 'infopathbeaconingui'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\editoractivexbeaconingui'
         {
              ValueName = 'editoractivexbeaconingui'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\disallowattachmentcustomization'
         {
              ValueName = 'disallowattachmentcustomization'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\enableintranetemailforms'
         {
              ValueName = 'enableintranetemailforms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\runmanagedcodefrominternet'
         {
              ValueName = 'runmanagedcodefrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\signaturewarning'
         {
              ValueName = 'signaturewarning'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\trusted locations\alllocationsdisabled'
         {
              ValueName = 'alllocationsdisabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security\trusted locations'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\disableinfopathforms'
         {
              ValueName = 'disableinfopathforms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\research\translation\useonline'
         {
              ValueName = 'useonline'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\research\translation'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\options\defaultformat'
         {
              ValueName = 'defaultformat'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\options'
              ValueData = '
'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\options\dontupdatelinks'
         {
              ValueName = 'dontupdatelinks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\options'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\options\warnrevisions'
         {
              ValueName = 'warnrevisions'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\options'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\options\custommarkupwarning'
         {
              ValueName = 'custommarkupwarning'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\options'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\wordbypassencryptedmacroscan'
         {
              ValueName = 'wordbypassencryptedmacroscan'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\accessvbom'
         {
              ValueName = 'accessvbom'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\word2files'
         {
              ValueName = 'word2files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\word2000files'
         {
              ValueName = 'word2000files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueData = 5

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\word60files'
         {
              ValueName = 'word60files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\word95files'
         {
              ValueName = 'word95files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueData = 5

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\word97files'
         {
              ValueName = 'word97files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueData = 5

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\wordxpfiles'
         {
              ValueName = 'wordxpfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueData = 5

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\filevalidation\enableonload'
         {
              ValueName = 'enableonload'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\filevalidation\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\filevalidation\disableeditfrompv'
         {
              ValueName = 'disableeditfrompv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\protectedview\disableinternetfilesinpv'
         {
              ValueName = 'disableinternetfilesinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\protectedview\disableunsafelocationsinpv'
         {
              ValueName = 'disableunsafelocationsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\trusted locations\alllocationsdisabled'
         {
              ValueName = 'alllocationsdisabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\trusted locations'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\trusted locations'
              ValueData = 0

         }#>

         Registry 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\savepassword'
         {
              ValueName = 'savepassword'
              ValueType = 'Dword'
              Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\enablesiphighsecuritymode'
         {
              ValueName = 'enablesiphighsecuritymode'
              ValueType = 'Dword'
              Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\disablehttpconnect'
         {
              ValueName = 'disablehttpconnect'
              ValueType = 'Dword'
              Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
              ValueData = 1

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\options\defaultformat'
         {
              ValueName = 'defaultformat'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\options'
              ValueData = 27

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 1

         }#>

         Registry 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\powerpointbypassencryptedmacroscan'
         {
              ValueName = 'powerpointbypassencryptedmacroscan'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = ''
              Ensure = 'Absent'

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\accessvbom'
         {
              ValueName = 'accessvbom'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 0

         }#>

         Registry 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\runprograms'
         {
              ValueName = 'runprograms'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = ''
              Ensure = 'Absent'

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\enableonload'
         {
              ValueName = 'enableonload'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = 1

         }#>

         Registry 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = ''
              Ensure = 'Absent'

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\disableeditfrompv'
         {
              ValueName = 'disableeditfrompv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableintranetcheck'
         {
              ValueName = 'disableintranetcheck'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations\alllocationsdisabled'
         {
              ValueName = 'alllocationsdisabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\ms project\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\ms project\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\ms project\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\ms project\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\ms project\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\ms project\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\ms project\security\trustwss'
         {
              ValueName = 'trustwss'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\ms project\security'
              ValueData = 0

         }#>

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PolicyVersion'
         {
              ValueName = 'PolicyVersion'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
              ValueData = 539

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
         {
              ValueName = 'EnableFirewall'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
         {
              ValueName = 'DefaultOutboundAction'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
         {
              ValueName = 'DefaultInboundAction'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize'
         {
              ValueName = 'LogFileSize'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
              ValueData = 16384

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets'
         {
              ValueName = 'LogDroppedPackets'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections'
         {
              ValueName = 'LogSuccessfulConnections'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall'
         {
              ValueName = 'EnableFirewall'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction'
         {
              ValueName = 'DefaultOutboundAction'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction'
         {
              ValueName = 'DefaultInboundAction'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize'
         {
              ValueName = 'LogFileSize'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
              ValueData = 16384

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets'
         {
              ValueName = 'LogDroppedPackets'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections'
         {
              ValueName = 'LogSuccessfulConnections'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall'
         {
              ValueName = 'EnableFirewall'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction'
         {
              ValueName = 'DefaultOutboundAction'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction'
         {
              ValueName = 'DefaultInboundAction'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge'
         {
              ValueName = 'AllowLocalPolicyMerge'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge'
         {
              ValueName = 'AllowLocalIPsecPolicyMerge'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize'
         {
              ValueName = 'LogFileSize'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
              ValueData = 16384

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets'
         {
              ValueName = 'LogDroppedPackets'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections'
         {
              ValueName = 'LogSuccessfulConnections'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
              ValueData = 1

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\defaultformat'
         {
              ValueName = 'defaultformat'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueData = 51

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\extractdatadisableui'
         {
              ValueName = 'extractdatadisableui'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions\fglobalsheet_37_1'
         {
              ValueName = 'fglobalsheet_37_1'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 1

         }#>

         Registry 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\excelbypassencryptedmacroscan'
         {
              ValueName = 'excelbypassencryptedmacroscan'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = ''
              Ensure = 'Absent'

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\accessvbom'
         {
              ValueName = 'accessvbom'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 2

         }#>

         Registry 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\webservicefunctionwarnings'
         {
              ValueName = 'webservicefunctionwarnings'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = ''
              Ensure = 'Absent'

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4macros'
         {
              ValueName = 'xl4macros'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4workbooks'
         {
              ValueName = 'xl4workbooks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4worksheets'
         {
              ValueName = 'xl4worksheets'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl95workbooks'
         {
              ValueName = 'xl95workbooks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 5

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl9597workbooksandtemplates'
         {
              ValueName = 'xl9597workbooksandtemplates'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 5

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\difandsylkfiles'
         {
              ValueName = 'difandsylkfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl2macros'
         {
              ValueName = 'xl2macros'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl2worksheets'
         {
              ValueName = 'xl2worksheets'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl3macros'
         {
              ValueName = 'xl3macros'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl3worksheets'
         {
              ValueName = 'xl3worksheets'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\htmlandxmlssfiles'
         {
              ValueName = 'htmlandxmlssfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\dbasefiles'
         {
              ValueName = 'dbasefiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\enableonload'
         {
              ValueName = 'enableonload'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = 1

         }#>

         Registry 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = ''
              Ensure = 'Absent'

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\disableeditfrompv'
         {
              ValueName = 'disableeditfrompv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableintranetcheck'
         {
              ValueName = 'disableintranetcheck'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations\alllocationsdisabled'
         {
              ValueName = 'alllocationsdisabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\portal\linkpublishingdisabled'
         {
              ValueName = 'linkpublishingdisabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\portal'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\macroruntimescanscope'
         {
              ValueName = 'macroruntimescanscope'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\drmencryptproperty'
         {
              ValueName = 'drmencryptproperty'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\defaultencryption12'
         {
              ValueName = 'defaultencryption12'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\openxmlencryption'
         {
              ValueName = 'openxmlencryption'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations\allow user locations'
         {
              ValueName = 'allow user locations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\access\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\access'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\excel\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\excel'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\infopath\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\infopath'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\outlook\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\outlook'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\powerpoint\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\powerpoint'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\project\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\project'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\publisher\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\publisher'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\visio\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\visio'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\word\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\word'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\trustcenter\trustbar'
         {
              ValueName = 'trustbar'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\trustcenter'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\internet\donotloadpictures'
         {
              ValueName = 'donotloadpictures'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\internet'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\extractdatadisableui'
         {
              ValueName = 'extractdatadisableui'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\disableautorepublish'
         {
              ValueName = 'disableautorepublish'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\disableautorepublishwarning'
         {
              ValueName = 'disableautorepublishwarning'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions\fupdateext_78_1'
         {
              ValueName = 'fupdateext_78_1'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\extensionhardening'
         {
              ValueName = 'extensionhardening'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\excelbypassencryptedmacroscan'
         {
              ValueName = 'excelbypassencryptedmacroscan'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 0
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\excel\security\excelbypassencryptedmacroscan')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\webservicefunctionwarnings'
         {
              ValueName = 'webservicefunctionwarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 1
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\excel\security\webservicefunctionwarnings')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\disableddeserverlaunch'
         {
              ValueName = 'disableddeserverlaunch'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\disableddeserverlookup'
         {
              ValueName = 'disableddeserverlookup'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\enableblockunsecurequeryfiles'
         {
              ValueName = 'enableblockunsecurequeryfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\dbasefiles'
         {
              ValueName = 'dbasefiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\difandsylkfiles'
         {
              ValueName = 'difandsylkfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl2macros'
         {
              ValueName = 'xl2macros'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl2worksheets'
         {
              ValueName = 'xl2worksheets'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl3macros'
         {
              ValueName = 'xl3macros'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl3worksheets'
         {
              ValueName = 'xl3worksheets'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4macros'
         {
              ValueName = 'xl4macros'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4workbooks'
         {
              ValueName = 'xl4workbooks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4worksheets'
         {
              ValueName = 'xl4worksheets'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl95workbooks'
         {
              ValueName = 'xl95workbooks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl9597workbooksandtemplates'
         {
              ValueName = 'xl9597workbooksandtemplates'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\htmlandxmlssfiles'
         {
              ValueName = 'htmlandxmlssfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\enableonload'
         {
              ValueName = 'enableonload'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = 1
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\openinprotectedview')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\disableeditfrompv'
         {
              ValueName = 'disableeditfrompv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\enabledatabasefileprotectedview'
         {
              ValueName = 'enabledatabasefileprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableinternetfilesinpv'
         {
              ValueName = 'disableinternetfilesinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableunsafelocationsinpv'
         {
              ValueName = 'disableunsafelocationsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\disallowattachmentcustomization'
         {
              ValueName = 'disallowattachmentcustomization'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\general\msgformat'
         {
              ValueName = 'msgformat'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\general'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\junkmailprotection'
         {
              ValueName = 'junkmailprotection'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\internet'
         {
              ValueName = 'internet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\junkmailenablelinks'
         {
              ValueName = 'junkmailenablelinks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\rpc\enablerpcencryption'
         {
              ValueName = 'enablerpcencryption'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\rpc'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\authenticationservice'
         {
              ValueName = 'authenticationservice'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 16

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\publicfolderscript'
         {
              ValueName = 'publicfolderscript'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\sharedfolderscript'
         {
              ValueName = 'sharedfolderscript'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\allowactivexoneoffforms'
         {
              ValueName = 'allowactivexoneoffforms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\publishtogaldisabled'
         {
              ValueName = 'publishtogaldisabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\minenckey'
         {
              ValueName = 'minenckey'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 168

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\warnaboutinvalid'
         {
              ValueName = 'warnaboutinvalid'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\usecrlchasing'
         {
              ValueName = 'usecrlchasing'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\adminsecuritymode'
         {
              ValueName = 'adminsecuritymode'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\allowuserstolowerattachments'
         {
              ValueName = 'allowuserstolowerattachments'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\showlevel1attach'
         {
              ValueName = 'showlevel1attach'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         Registry 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel1'
         {
              ValueName = 'fileextensionsremovelevel1'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = ''
              Ensure = 'Absent'

         }

         Registry 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel2'
         {
              ValueName = 'fileextensionsremovelevel2'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = ''
              Ensure = 'Absent'

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\enableoneoffformscripts'
         {
              ValueName = 'enableoneoffformscripts'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomcustomaction'
         {
              ValueName = 'promptoomcustomaction'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressbookaccess'
         {
              ValueName = 'promptoomaddressbookaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomformulaaccess'
         {
              ValueName = 'promptoomformulaaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsaveas'
         {
              ValueName = 'promptoomsaveas'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressinformationaccess'
         {
              ValueName = 'promptoomaddressinformationaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoommeetingtaskrequestresponse'
         {
              ValueName = 'promptoommeetingtaskrequestresponse'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsend'
         {
              ValueName = 'promptoomsend'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\level'
         {
              ValueName = 'level'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\runprograms'
         {
              ValueName = 'runprograms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 0
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\runprograms')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\powerpointbypassencryptedmacroscan'
         {
              ValueName = 'powerpointbypassencryptedmacroscan'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 0
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\powerpointbypassencryptedmacroscan')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock\binaryfiles'
         {
              ValueName = 'binaryfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\enableonload'
         {
              ValueName = 'enableonload'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = 1
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\openinprotectedview')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\disableeditfrompv'
         {
              ValueName = 'disableeditfrompv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableinternetfilesinpv'
         {
              ValueName = 'disableinternetfilesinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableunsafelocationsinpv'
         {
              ValueName = 'disableunsafelocationsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio2000files'
         {
              ValueName = 'visio2000files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio2003files'
         {
              ValueName = 'visio2003files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio50andearlierfiles'
         {
              ValueName = 'visio50andearlierfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\wordbypassencryptedmacroscan'
         {
              ValueName = 'wordbypassencryptedmacroscan'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 0
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\word\security\wordbypassencryptedmacroscan')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2files'
         {
              ValueName = 'word2files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2000files'
         {
              ValueName = 'word2000files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2003files'
         {
              ValueName = 'word2003files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2007files'
         {
              ValueName = 'word2007files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word60files'
         {
              ValueName = 'word60files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word95files'
         {
              ValueName = 'word95files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word97files'
         {
              ValueName = 'word97files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\wordxpfiles'
         {
              ValueName = 'wordxpfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = 1
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\word\security\filevalidation\openinprotectedview')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\disableeditfrompv'
         {
              ValueName = 'disableeditfrompv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\enableonload'
         {
              ValueName = 'enableonload'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableinternetfilesinpv'
         {
              ValueName = 'disableinternetfilesinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableunsafelocationsinpv'
         {
              ValueName = 'disableunsafelocationsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\uficontrols'
         {
              ValueName = 'uficontrols'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 6

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecurity'
         {
              ValueName = 'automationsecurity'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecuritypublisher'
         {
              ValueName = 'automationsecuritypublisher'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\smart tag\neverloadmanifests'
         {
              ValueName = 'neverloadmanifests'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\smart tag'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\vba\security\loadcontrolsinforms'
         {
              ValueName = 'loadcontrolsinforms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\vba\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\internet\donotunderlinehyperlinks'
         {
              ValueName = 'donotunderlinehyperlinks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\internet'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\modaltrustdecisiononly'
         {
              ValueName = 'modaltrustdecisiononly'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\settings\default file format'
         {
              ValueName = 'default file format'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\settings'
              ValueData = 12

         }#>

         Registry 'Registry(POL): HKLM:\Software\Classes\batfile\shell\runasuser\SuppressionPolicy'
         {
              ValueName = 'SuppressionPolicy'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Classes\batfile\shell\runasuser'
              ValueData = 4096

         }

         Registry 'Registry(POL): HKLM:\Software\Classes\cmdfile\shell\runasuser\SuppressionPolicy'
         {
              ValueName = 'SuppressionPolicy'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Classes\cmdfile\shell\runasuser'
              ValueData = 4096

         }

         Registry 'Registry(POL): HKLM:\Software\Classes\exefile\shell\runasuser\SuppressionPolicy'
         {
              ValueName = 'SuppressionPolicy'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Classes\exefile\shell\runasuser'
              ValueData = 4096

         }

         Registry 'Registry(POL): HKLM:\Software\Classes\mscfile\shell\runasuser\SuppressionPolicy'
         {
              ValueName = 'SuppressionPolicy'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Classes\mscfile\shell\runasuser'
              ValueData = 4096

         }

         Registry 'Registry(POL): HKLM:\Software\Microsoft\wcmsvc\wifinetworkmanager\config\AutoConnectAllowedOEM'
         {
              ValueName = 'AutoConnectAllowedOEM'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\wcmsvc\wifinetworkmanager\config'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
         {
              ValueName = 'EnumerateAdministrators'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices'
         {
              ValueName = 'NoWebServices'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
         {
              ValueName = 'NoAutorun'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
         {
              ValueName = 'NoDriveTypeAutoRun'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 255

         }

         Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoStartBanner'
         {
              ValueName = 'NoStartBanner'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
         {
              ValueName = 'MSAOptional'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
         {
              ValueName = 'DisableAutomaticRestartSignOn'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
         {
              ValueName = 'LocalAccountTokenFilterPolicy'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
         {
              ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing'
         {
              ValueName = 'EnhancedAntiSpoofing'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\EccCurves'
         {
              ValueName = 'EccCurves'
              ValueType = 'MultiString'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
              ValueData = 'NistP384 NistP256 '

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseAdvancedStartup'
         {
              ValueName = 'UseAdvancedStartup'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\FVE'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\EnableBDEWithNoTPM'
         {
              ValueName = 'EnableBDEWithNoTPM'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\FVE'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseTPM'
         {
              ValueName = 'UseTPM'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\FVE'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseTPMPIN'
         {
              ValueName = 'UseTPMPIN'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\FVE'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseTPMKey'
         {
              ValueName = 'UseTPMKey'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\FVE'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseTPMKeyPIN'
         {
              ValueName = 'UseTPMKeyPIN'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\FVE'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\MinimumPIN'
         {
              ValueName = 'MinimumPIN'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\FVE'
              ValueData = 6

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
         {
              ValueName = 'DisableEnclosureDownload'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Internet Settings\PreventCertErrorOverrides'
         {
              ValueName = 'PreventCertErrorOverrides'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Internet Settings'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main\FormSuggest Passwords'
         {
              ValueName = 'FormSuggest Passwords'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main'
              ValueData = 'no'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\EnabledV9'
         {
              ValueName = 'EnabledV9'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverrideAppRepUnknown'
         {
              ValueName = 'PreventOverrideAppRepUnknown'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverride'
         {
              ValueName = 'PreventOverride'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList\1111-2222-3333-4444'
         {
              ValueName = '1111-2222-3333-4444'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList'
              ValueData = '1111-2222-3333-4444'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\PassportForWork\RequireSecurityDevice'
         {
              ValueName = 'RequireSecurityDevice'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\PassportForWork'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices\TPM12'
         {
              ValueName = 'TPM12'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\PassportForWork\PINComplexity\MinimumPINLength'
         {
              ValueName = 'MinimumPINLength'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\PassportForWork\PINComplexity'
              ValueData = 6

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
         {
              ValueName = 'DCSettingIndex'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
         {
              ValueName = 'ACSettingIndex'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppCompat\DisableInventory'
         {
              ValueName = 'DisableInventory'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy\LetAppsActivateWithVoiceAboveLock'
         {
              ValueName = 'LetAppsActivateWithVoiceAboveLock'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures'
         {
              ValueName = 'DisableWindowsConsumerFeatures'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
         {
              ValueName = 'AllowProtectedCreds'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
         {
              ValueName = 'AllowTelemetry'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\LimitEnhancedDiagnosticDataWindowsAnalytics'
         {
              ValueName = 'LimitEnhancedDiagnosticDataWindowsAnalytics'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
         {
              ValueName = 'DODownloadMode'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
         {
              ValueName = 'EnableVirtualizationBasedSecurity'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
         {
              ValueName = 'RequirePlatformSecurityFeatures'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
         {
              ValueName = 'HypervisorEnforcedCodeIntegrity'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired'
         {
              ValueName = 'HVCIMATRequired'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
         {
              ValueName = 'LsaCfgFlags'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch'
         {
              ValueName = 'ConfigureSystemGuardLaunch'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
         {
              ValueName = 'MaxSize'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
              ValueData = 32768

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
         {
              ValueName = 'MaxSize'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
              ValueData = 1024000

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
         {
              ValueName = 'MaxSize'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
              ValueData = 32768

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
         {
              ValueName = 'NoAutoplayfornonVolume'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\GameDVR\AllowGameDVR'
         {
              ValueName = 'AllowGameDVR'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\GameDVR'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
         {
              ValueName = 'NoBackgroundPolicy'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
         {
              ValueName = 'NoGPOListChanges'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
         {
              ValueName = 'EnableUserControl'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
         {
              ValueName = 'AlwaysInstallElevated'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy'
         {
              ValueName = 'DeviceEnumerationPolicy'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
         {
              ValueName = 'AllowInsecureGuestAuth'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI'
         {
              ValueName = 'NC_ShowSharedAccessUI'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\*\SYSVOL'
         {
              ValueName = '\\*\SYSVOL'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
              ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\*\NETLOGON'
         {
              ValueName = '\\*\NETLOGON'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
              ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera'
         {
              ValueName = 'NoLockScreenCamera'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
         {
              ValueName = 'NoLockScreenSlideshow'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
         {
              ValueName = 'EnableScriptBlockLogging'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
              ValueData = 1

         }

         Registry 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
         {
              ValueName = 'EnableScriptBlockInvocationLogging'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
              ValueData = ''
              Ensure = 'Absent'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
         {
              ValueName = 'DontDisplayNetworkSelectionUI'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
         {
              ValueName = 'EnumerateLocalUsers'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen'
         {
              ValueName = 'EnableSmartScreen'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel'
         {
              ValueName = 'ShellSmartScreenLevel'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
              ValueData = 'Block'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\AllowDomainPINLogon'
         {
              ValueName = 'AllowDomainPINLogon'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain'
         {
              ValueName = 'fBlockNonDomain'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
         {
              ValueName = 'AllowIndexingEncryptedStoresOrItems'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
         {
              ValueName = 'AllowBasic'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
         {
              ValueName = 'AllowUnencryptedTraffic'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
         {
              ValueName = 'AllowDigest'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
         {
              ValueName = 'AllowBasic'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
         {
              ValueName = 'AllowUnencryptedTraffic'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
         {
              ValueName = 'DisableRunAs'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender ExploitGuard\Exploit Protection\ExploitProtectionSettings'
         {
              ValueName = 'ExploitProtectionSettings'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender ExploitGuard\Exploit Protection'
              ValueData = 'C:\temp\Windows Defender\DOD_EP_V3.xml'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
         {
              ValueName = 'DisableWebPnPDownload'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
         {
              ValueName = 'DisableHTTPPrinting'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
         {
              ValueName = 'RestrictRemoteClients'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
         {
              ValueName = 'fAllowToGetHelp'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 0

         }

         Registry 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
         {
              ValueName = 'fAllowFullControl'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
              Ensure = 'Absent'

         }

         Registry 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
         {
              ValueName = 'MaxTicketExpiry'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
              Ensure = 'Absent'

         }

         Registry 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
         {
              ValueName = 'MaxTicketExpiryUnits'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
              Ensure = 'Absent'

         }

         Registry 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
         {
              ValueName = 'fUseMailto'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
              Ensure = 'Absent'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
         {
              ValueName = 'DisablePasswordSaving'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
         {
              ValueName = 'fDisableCdm'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
         {
              ValueName = 'fPromptForPassword'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
         {
              ValueName = 'fEncryptRPCTraffic'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
         {
              ValueName = 'MinEncryptionLevel'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace'
         {
              ValueName = 'AllowWindowsInkWorkspace'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
         {
              ValueName = 'UseLogonCredential'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\System\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation'
         {
              ValueName = 'DisableExceptionChainValidation'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\kernel'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\System\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
         {
              ValueName = 'DriverLoadPolicy'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Policies\EarlyLaunch'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
         {
              ValueName = 'SMB1'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\System\CurrentControlSet\Services\MrxSmb10\Start'
         {
              ValueName = 'Start'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\MrxSmb10'
              ValueData = 4

         }

         Registry 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
         {
              ValueName = 'NoNameReleaseOnDemand'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\Netbt\Parameters'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
         {
              ValueName = 'DisableIPSourceRouting'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
         {
              ValueName = 'EnableICMPRedirect'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
         {
              ValueName = 'DisableIPSourceRouting'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'
              ValueData = 2

         }

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Appx\EnforcementMode'
         {
              ValueName = 'EnforcementMode'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Appx'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Appx\a9e18c21-ff8f-43cf-b9fc-db40eed693ba\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Appx\a9e18c21-ff8f-43cf-b9fc-db40eed693ba'
              ValueData = '<FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\EnforcementMode'
         {
              ValueName = 'EnforcementMode'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\1d04fdc7-5e29-45b1-a0d7-f7e9293774f8\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\1d04fdc7-5e29-45b1-a0d7-f7e9293774f8'
              ValueData = '<FilePathRule Id="1d04fdc7-5e29-45b1-a0d7-f7e9293774f8" Name="Allows administrators to execute all DLLs" Description="Allows members of the local Administrators group to load all DLLs." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\7ca2deae-991c-4e26-b688-98137f9cc777\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\7ca2deae-991c-4e26-b688-98137f9cc777'
              ValueData = '<FilePathRule Id="7ca2deae-991c-4e26-b688-98137f9cc777" Name="Allow everyone to execute all DLLs located in the Windows folder" Description="Allows members of the Everyone group to load DLLs located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions><Exceptions><FilePathCondition Path="%SYSTEM32%\catroot2\*"/><FilePathCondition Path="%SYSTEM32%\com\dmp\*"/><FilePathCondition Path="%SYSTEM32%\FxsTmp\*"/><FilePathCondition Path="%SYSTEM32%\spool\drivers\color\*"/><FilePathCondition Path="%SYSTEM32%\spool\PRINTERS\*"/><FilePathCondition Path="%SYSTEM32%\spool\SERVERS\*"/><FilePathCondition Path="%SYSTEM32%\Tasks\*"/><FilePathCondition Path="%WINDIR%\Debug\*"/><FilePathCondition Path="%WINDIR%\PCHEALTH\ERRORREP\*"/><FilePathCondition Path="%WINDIR%\Registration\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\*"/><FilePathCondition Path="%WINDIR%\Tasks\*"/><FilePathCondition Path="%WINDIR%\Temp\*"/><FilePathCondition Path="%WINDIR%\tracing\*"/></Exceptions></FilePathRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\f36fbeba-ab50-48c0-9361-41af365d82ce\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\f36fbeba-ab50-48c0-9361-41af365d82ce'
              ValueData = '<FilePathRule Id="f36fbeba-ab50-48c0-9361-41af365d82ce" Name="Allow everyone to execute all DLLs located in the Program Files folder" Description="Allows members of the Everyone group to load DLLs that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\EnforcementMode'
         {
              ValueName = 'EnforcementMode'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\1712f2de-e1b6-4d3d-85a9-a7da49b796c1\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\1712f2de-e1b6-4d3d-85a9-a7da49b796c1'
              ValueData = '<FilePathRule Id="1712f2de-e1b6-4d3d-85a9-a7da49b796c1" Name="Allow everyone to execute all files located in the Program Files folder" Description="Allows members of the Everyone group to run applications that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\187ae870-255e-42d7-8ef9-9a8434a70716\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\187ae870-255e-42d7-8ef9-9a8434a70716'
              ValueData = '<FilePublisherRule Id="187ae870-255e-42d7-8ef9-9a8434a70716" Name="Prevent administrators from easily running the Internet Explorer web browser" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="WINDOWS® INTERNET EXPLORER" BinaryName="IEXPLORE.EXE"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\230ebde7-123f-4f56-9caf-a412e5265300\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\230ebde7-123f-4f56-9caf-a412e5265300'
              ValueData = '<FilePublisherRule Id="230ebde7-123f-4f56-9caf-a412e5265300" Name="Prevent administrators from easily running the Outlook email client" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT OFFICE OUTLOOK" BinaryName="OUTLOOK.EXE"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\54d44e7f-44b7-4d8d-961e-6d9c47e03196\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\54d44e7f-44b7-4d8d-961e-6d9c47e03196'
              ValueData = '<FilePublisherRule Id="54d44e7f-44b7-4d8d-961e-6d9c47e03196" Name="Prevent administrators from easily running the Thunderbird email client" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MOZILLA MESSAGING INC., L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" ProductName="THUNDERBIRD" BinaryName="thunderbird.exe"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\97bca7b1-6ff4-40a5-a1fe-e8e8535f6e1e\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\97bca7b1-6ff4-40a5-a1fe-e8e8535f6e1e'
              ValueData = '<FilePublisherRule Id="97bca7b1-6ff4-40a5-a1fe-e8e8535f6e1e" Name="Prevent administrators from easily running the Chrome web browser" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=GOOGLE INC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" ProductName="GOOGLE CHROME" BinaryName="chrome.exe"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\980f805b-bc66-43c7-95c4-90ef50fe5b04\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\980f805b-bc66-43c7-95c4-90ef50fe5b04'
              ValueData = '<FilePublisherRule Id="980f805b-bc66-43c7-95c4-90ef50fe5b04" Name="Prevent administrators from easily running the Firefox web browser" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MOZILLA CORPORATION, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" ProductName="FIREFOX" BinaryName="firefox.exe"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\a88c9192-bbed-4dfe-b435-d0ca25f6576e\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\a88c9192-bbed-4dfe-b435-d0ca25f6576e'
              ValueData = '<FilePublisherRule Id="a88c9192-bbed-4dfe-b435-d0ca25f6576e" Name="Prevent administrators from easily running the Opera web browser" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=OPERA SOFTWARE ASA, S=OSLO, C=NO" ProductName="OPERA" BinaryName="opera.exe"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\afd4074c-4b47-4b55-bb6d-f35ea215408b\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\afd4074c-4b47-4b55-bb6d-f35ea215408b'
              ValueData = '<FilePathRule Id="afd4074c-4b47-4b55-bb6d-f35ea215408b" Name="Allow everyone to execute all files located in the Windows folder" Description="Allows members of the Everyone group to run applications that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions><Exceptions><FilePathCondition Path="%SYSTEM32%\catroot2\*"/><FilePathCondition Path="%SYSTEM32%\com\dmp\*"/><FilePathCondition Path="%SYSTEM32%\FxsTmp\*"/><FilePathCondition Path="%SYSTEM32%\spool\drivers\color\*"/><FilePathCondition Path="%SYSTEM32%\spool\PRINTERS\*"/><FilePathCondition Path="%SYSTEM32%\spool\SERVERS\*"/><FilePathCondition Path="%SYSTEM32%\Tasks\*"/><FilePathCondition Path="%WINDIR%\Debug\*"/><FilePathCondition Path="%WINDIR%\PCHEALTH\ERRORREP\*"/><FilePathCondition Path="%WINDIR%\Registration\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\*"/><FilePathCondition Path="%WINDIR%\Tasks\*"/><FilePathCondition Path="%WINDIR%\Temp\*"/><FilePathCondition Path="%WINDIR%\tracing\*"/></Exceptions></FilePathRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\f301f291-10d9-4423-8f9c-a78afe9d4ea5\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\f301f291-10d9-4423-8f9c-a78afe9d4ea5'
              ValueData = '<FilePathRule Id="f301f291-10d9-4423-8f9c-a78afe9d4ea5" Name="Allow administrators to execute all files" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\f53c8fc8-d0dd-43c4-b874-57f31ba6f4aa\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\f53c8fc8-d0dd-43c4-b874-57f31ba6f4aa'
              ValueData = '<FilePublisherRule Id="f53c8fc8-d0dd-43c4-b874-57f31ba6f4aa" Name="Prevent administrators from easily running the Safari web browser" Description="" UserOrGroupSid="S-1-5-32-544" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=APPLE INC., L=CUPERTINO, S=CALIFORNIA, C=US" ProductName="SAFARI" BinaryName="Safari.exe"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi\EnforcementMode'
         {
              ValueName = 'EnforcementMode'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi\0b075828-da4a-41fc-b3b4-9ac83ad18add\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi\0b075828-da4a-41fc-b3b4-9ac83ad18add'
              ValueData = '<FilePathRule Id="0b075828-da4a-41fc-b3b4-9ac83ad18add" Name="Allow everyone to run all Windows Installer files located in the Windows\Installer folder." Description="Allows members of the Everyone group to run all Windows Installer files located in %systemdrive%\Windows\Installer." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\Installer\*"/></Conditions></FilePathRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi\4833728f-cf7e-4797-a847-c979e29b597a\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi\4833728f-cf7e-4797-a847-c979e29b597a'
              ValueData = '<FilePathRule Id="4833728f-cf7e-4797-a847-c979e29b597a" Name="Allow administrators to run all Windows Installer files" Description="Allows members of the local Administrators group to run all Windows Installer files." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\EnforcementMode'
         {
              ValueName = 'EnforcementMode'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\4a4170c6-feb8-44f6-bebf-78a319f197fe\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\4a4170c6-feb8-44f6-bebf-78a319f197fe'
              ValueData = '<FilePathRule Id="4a4170c6-feb8-44f6-bebf-78a319f197fe" Name="Allow everyone to run all scripts located in the Program Files folder" Description="Allows members of the Everyone group to run scripts that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\8f42d1d3-5f29-469d-8f37-6f01f6c3b2f4\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\8f42d1d3-5f29-469d-8f37-6f01f6c3b2f4'
              ValueData = '<FilePathRule Id="8f42d1d3-5f29-469d-8f37-6f01f6c3b2f4" Name="Allow everyone to run all scripts located in the Windows folder" Description="Allows members of the Everyone group to run scripts that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions><Exceptions><FilePathCondition Path="%SYSTEM32%\catroot2\*"/><FilePathCondition Path="%SYSTEM32%\com\dmp\*"/><FilePathCondition Path="%SYSTEM32%\FxsTmp\*"/><FilePathCondition Path="%SYSTEM32%\spool\drivers\color\*"/><FilePathCondition Path="%SYSTEM32%\spool\PRINTERS\*"/><FilePathCondition Path="%SYSTEM32%\spool\SERVERS\*"/><FilePathCondition Path="%SYSTEM32%\Tasks\*"/><FilePathCondition Path="%WINDIR%\Debug\*"/><FilePathCondition Path="%WINDIR%\PCHEALTH\ERRORREP\*"/><FilePathCondition Path="%WINDIR%\Registration\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp\*"/><FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\*"/><FilePathCondition Path="%WINDIR%\Tasks\*"/><FilePathCondition Path="%WINDIR%\Temp\*"/><FilePathCondition Path="%WINDIR%\tracing\*"/></Exceptions></FilePathRule>
'

         }#>

         <#Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\ed97d0cb-15ff-430f-b82c-8d7832957725\Value'
         {
              ValueName = 'Value'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\ed97d0cb-15ff-430f-b82c-8d7832957725'
              ValueData = '<FilePathRule Id="ed97d0cb-15ff-430f-b82c-8d7832957725" Name="All scripts" Description="Allows members of the local Administrators group to run all scripts." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
'

         }#>

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0

         }

         <#Registry 'Registry(POL): HKCU:\SOFTWARE\Microsoft\OneDrive\DisablePersonalSync'
         {
              ValueName = 'DisablePersonalSync'
              ValueType = 'Dword'
              Key = 'HKCU:\SOFTWARE\Microsoft\OneDrive'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 2

         }#>

         Registry 'DEL_CU:\keycupoliciesmsvbasecurity\loadcontrolsinforms'
         {
              ValueName = 'loadcontrolsinforms'
              ValueType = 'String'
              Key = 'HKCU:\keycupoliciesmsvbasecurity'
              ValueData = ''
              Ensure = 'Absent'

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\qmenable'
         {
              ValueName = 'qmenable'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\updatereliabilitydata'
         {
              ValueName = 'updatereliabilitydata'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\broadcast\disabledefaultservice'
         {
              ValueName = 'disabledefaultservice'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\broadcast'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\broadcast\disableprogrammaticaccess'
         {
              ValueName = 'disableprogrammaticaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\broadcast'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\documentinformationpanel\beaconing'
         {
              ValueName = 'beaconing'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\documentinformationpanel'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\drm\includehtml'
         {
              ValueName = 'includehtml'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\drm'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\drm\requireconnection'
         {
              ValueName = 'requireconnection'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\drm'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\drm\disablecreation'
         {
              ValueName = 'disablecreation'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\drm'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\feedback\includescreenshot'
         {
              ValueName = 'includescreenshot'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\feedback'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\feedback\enabled'
         {
              ValueName = 'enabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\feedback'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\fixedformat\disablefixedformatdocproperties'
         {
              ValueName = 'disablefixedformatdocproperties'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\fixedformat'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\general\shownfirstrunoptin'
         {
              ValueName = 'shownfirstrunoptin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\general'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\general\skydrivesigninoption'
         {
              ValueName = 'skydrivesigninoption'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\general'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\internet\opendocumentsreadwritewhilebrowsing'
         {
              ValueName = 'opendocumentsreadwritewhilebrowsing'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\internet'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\internet\relyonvml'
         {
              ValueName = 'relyonvml'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\internet'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\internet\useonlinecontent'
         {
              ValueName = 'useonlinecontent'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\internet'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\portal\linkpublishingdisabled'
         {
              ValueName = 'linkpublishingdisabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\portal'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\ptwatson\ptwoptin'
         {
              ValueName = 'ptwoptin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\ptwatson'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\roaming\roamingsettingsdisabled'
         {
              ValueName = 'roamingsettingsdisabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\roaming'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\defaultencryption12'
         {
              ValueName = 'defaultencryption12'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\openxmlencryption'
         {
              ValueName = 'openxmlencryption'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\disablehyperlinkwarning'
         {
              ValueName = 'disablehyperlinkwarning'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\disablepasswordui'
         {
              ValueName = 'disablepasswordui'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\openxmlencryptproperty'
         {
              ValueName = 'openxmlencryptproperty'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\drmencryptproperty'
         {
              ValueName = 'drmencryptproperty'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\encryptdocprops'
         {
              ValueName = 'encryptdocprops'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\trusted locations\allow user locations'
         {
              ValueName = 'allow user locations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\services\fax\nofax'
         {
              ValueName = 'nofax'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\services\fax'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\signatures\enablecreationofweakxpsignatures'
         {
              ValueName = 'enablecreationofweakxpsignatures'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\signatures'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\signatures\suppressextsigningsvcs'
         {
              ValueName = 'suppressextsigningsvcs'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\signatures'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\signin\signinoptions'
         {
              ValueName = 'signinoptions'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\signin'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\trustcenter\trustbar'
         {
              ValueName = 'trustbar'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\trustcenter'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\firstrun\disablemovie'
         {
              ValueName = 'disablemovie'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\firstrun'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\firstrun\bootedrtm'
         {
              ValueName = 'bootedrtm'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\firstrun'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\gfx\disablescreenshotautohyperlink'
         {
              ValueName = 'disablescreenshotautohyperlink'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\gfx'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\osm\enableupload'
         {
              ValueName = 'enableupload'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\osm'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\osm\enablefileobfuscation'
         {
              ValueName = 'enablefileobfuscation'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\osm'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\osm\enablelogging'
         {
              ValueName = 'enablelogging'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\osm'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\wef\trustedcatalogs\requireserververification'
         {
              ValueName = 'requireserververification'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\wef\trustedcatalogs'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\wef\trustedcatalogs\disableomexcatalogs'
         {
              ValueName = 'disableomexcatalogs'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\wef\trustedcatalogs'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\blog\disableblog'
         {
              ValueName = 'disableblog'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\blog'
              ValueData = 1

         }#>

         <#Registry 'DEL_CU:\software\policies\microsoft\office\common\security\uficontrols'
         {
              ValueName = 'uficontrols'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = ''
              Ensure = 'Absent'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecurity'
         {
              ValueName = 'automationsecurity'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\smart tag\neverloadmanifests'
         {
              ValueName = 'neverloadmanifests'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\smart tag'
              ValueData = 1

         }#>

         Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext\RunThisTimeEnabled'
         {
              ValueName = 'RunThisTimeEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext\VersionCheckEnabled'
         {
              ValueName = 'VersionCheckEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel\History'
         {
              ValueName = 'History'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Download\RunInvalidSignatures'
         {
              ValueName = 'RunInvalidSignatures'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Download\CheckExeSignatures'
         {
              ValueName = 'CheckExeSignatures'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
              ValueData = 'yes'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\IEDevTools\Disabled'
         {
              ValueName = 'Disabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\IEDevTools'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\DisableEPMCompat'
         {
              ValueName = 'DisableEPMCompat'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\Isolation64Bit'
         {
              ValueName = 'Isolation64Bit'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\Isolation'
         {
              ValueName = 'Isolation'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
              ValueData = 'PMEM'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverride'
         {
              ValueName = 'PreventOverride'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverrideAppRepUnknown'
         {
              ValueName = 'PreventOverrideAppRepUnknown'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\EnabledV9'
         {
              ValueName = 'EnabledV9'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\ClearBrowsingHistoryOnExit'
         {
              ValueName = 'ClearBrowsingHistoryOnExit'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\CleanHistory'
         {
              ValueName = 'CleanHistory'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\EnableInPrivateBrowsing'
         {
              ValueName = 'EnableInPrivateBrowsing'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions\NoCrashDetection'
         {
              ValueName = 'NoCrashDetection'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\DisableSecuritySettingsCheck'
         {
              ValueName = 'DisableSecuritySettingsCheck'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX\BlockNonAdminActiveXInstall'
         {
              ValueName = 'BlockNonAdminActiveXInstall'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_zones_map_edit'
         {
              ValueName = 'Security_zones_map_edit'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_options_edit'
         {
              ValueName = 'Security_options_edit'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_HKLM_only'
         {
              ValueName = 'Security_HKLM_only'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\PreventIgnoreCertErrors'
         {
              ValueName = 'PreventIgnoreCertErrors'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\CertificateRevocation'
         {
              ValueName = 'CertificateRevocation'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\SecureProtocols'
         {
              ValueName = 'SecureProtocols'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 2560

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\WarnOnBadCertRecving'
         {
              ValueName = 'WarnOnBadCertRecving'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\EnableSSL3Fallback'
         {
              ValueName = 'EnableSSL3Fallback'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0\1C00'
         {
              ValueName = '1C00'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1\1C00'
         {
              ValueName = '1C00'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2\1C00'
         {
              ValueName = '1C00'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4\1C00'
         {
              ValueName = '1C00'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History\DaysToKeep'
         {
              ValueName = 'DaysToKeep'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History'
              ValueData = 40

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\UNCAsIntranet'
         {
              ValueName = 'UNCAsIntranet'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\270C'
         {
              ValueName = '270C'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1C00'
         {
              ValueName = '1C00'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\270C'
         {
              ValueName = '270C'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1201'
         {
              ValueName = '1201'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1C00'
         {
              ValueName = '1C00'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
              ValueData = 65536

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\270C'
         {
              ValueName = '270C'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1201'
         {
              ValueName = '1201'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1C00'
         {
              ValueName = '1C00'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
              ValueData = 65536

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1406'
         {
              ValueName = '1406'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1407'
         {
              ValueName = '1407'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1802'
         {
              ValueName = '1802'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2402'
         {
              ValueName = '2402'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120b'
         {
              ValueName = '120b'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120c'
         {
              ValueName = '120c'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1206'
         {
              ValueName = '1206'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2102'
         {
              ValueName = '2102'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1209'
         {
              ValueName = '1209'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2103'
         {
              ValueName = '2103'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2200'
         {
              ValueName = '2200'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\270C'
         {
              ValueName = '270C'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1001'
         {
              ValueName = '1001'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1004'
         {
              ValueName = '1004'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2709'
         {
              ValueName = '2709'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2708'
         {
              ValueName = '2708'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\160A'
         {
              ValueName = '160A'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1201'
         {
              ValueName = '1201'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1C00'
         {
              ValueName = '1C00'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1804'
         {
              ValueName = '1804'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1A00'
         {
              ValueName = '1A00'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 65536

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1607'
         {
              ValueName = '1607'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2004'
         {
              ValueName = '2004'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2001'
         {
              ValueName = '2001'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1806'
         {
              ValueName = '1806'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1409'
         {
              ValueName = '1409'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2500'
         {
              ValueName = '2500'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2301'
         {
              ValueName = '2301'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1809'
         {
              ValueName = '1809'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1606'
         {
              ValueName = '1606'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2101'
         {
              ValueName = '2101'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\140C'
         {
              ValueName = '140C'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1406'
         {
              ValueName = '1406'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1400'
         {
              ValueName = '1400'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2000'
         {
              ValueName = '2000'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1407'
         {
              ValueName = '1407'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1802'
         {
              ValueName = '1802'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1803'
         {
              ValueName = '1803'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2402'
         {
              ValueName = '2402'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1608'
         {
              ValueName = '1608'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120b'
         {
              ValueName = '120b'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120c'
         {
              ValueName = '120c'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1206'
         {
              ValueName = '1206'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2102'
         {
              ValueName = '2102'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1209'
         {
              ValueName = '1209'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2103'
         {
              ValueName = '2103'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2200'
         {
              ValueName = '2200'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\270C'
         {
              ValueName = '270C'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1001'
         {
              ValueName = '1001'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1004'
         {
              ValueName = '1004'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2709'
         {
              ValueName = '2709'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2708'
         {
              ValueName = '2708'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\160A'
         {
              ValueName = '160A'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1201'
         {
              ValueName = '1201'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1C00'
         {
              ValueName = '1C00'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1804'
         {
              ValueName = '1804'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1A00'
         {
              ValueName = '1A00'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 196608

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1607'
         {
              ValueName = '1607'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2004'
         {
              ValueName = '2004'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1200'
         {
              ValueName = '1200'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1405'
         {
              ValueName = '1405'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1402'
         {
              ValueName = '1402'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1806'
         {
              ValueName = '1806'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1409'
         {
              ValueName = '1409'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2500'
         {
              ValueName = '2500'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2301'
         {
              ValueName = '2301'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1809'
         {
              ValueName = '1809'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1606'
         {
              ValueName = '1606'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2101'
         {
              ValueName = '2101'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2001'
         {
              ValueName = '2001'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\140C'
         {
              ValueName = '140C'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3

         }

         <#Registry 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\2015\AVGeneral\bFIPSMode'
         {
              ValueName = 'bFIPSMode'
              ValueType = 'Dword'
              Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\2015\AVGeneral'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\2015\Security\cDigSig\cAdobeDownload\bLoadSettingsFromURL'
         {
              ValueName = 'bLoadSettingsFromURL'
              ValueType = 'Dword'
              Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\2015\Security\cDigSig\cAdobeDownload'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\2015\Security\cDigSig\cEUTLDownload\bLoadSettingsFromURL'
         {
              ValueName = 'bLoadSettingsFromURL'
              ValueType = 'Dword'
              Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\2015\Security\cDigSig\cEUTLDownload'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\promptforbadfiles'
         {
              ValueName = 'promptforbadfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecuritypublisher'
         {
              ValueName = 'automationsecuritypublisher'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\AVGeneral\bFIPSMode'
         {
              ValueName = 'bFIPSMode'
              ValueType = 'Dword'
              Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\AVGeneral'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cAdobeDownload\bLoadSettingsFromURL'
         {
              ValueName = 'bLoadSettingsFromURL'
              ValueType = 'Dword'
              Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cAdobeDownload'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cEUTLDownload\bLoadSettingsFromURL'
         {
              ValueName = 'bLoadSettingsFromURL'
              ValueType = 'Dword'
              Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cEUTLDownload'
              ValueData = 0

         }#>

         <#Registry 'DEL_CU:\keycupoliciesmsvbasecurity\loadcontrolsinforms'
         {
              ValueName = 'loadcontrolsinforms'
              ValueType = 'String'
              Key = 'HKCU:\keycupoliciesmsvbasecurity'
              ValueData = ''
              Ensure = 'Absent'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\sendcustomerdata'
         {
              ValueName = 'sendcustomerdata'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\broadcast\disabledefaultservice'
         {
              ValueName = 'disabledefaultservice'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\broadcast'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\broadcast\disableprogrammaticaccess'
         {
              ValueName = 'disableprogrammaticaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\broadcast'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\drm\requireconnection'
         {
              ValueName = 'requireconnection'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\drm'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\feedback\includescreenshot'
         {
              ValueName = 'includescreenshot'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\feedback'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\fixedformat\disablefixedformatdocproperties'
         {
              ValueName = 'disablefixedformatdocproperties'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\fixedformat'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\ptwatson\ptwoptin'
         {
              ValueName = 'ptwoptin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\ptwatson'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\drmencryptproperty'
         {
              ValueName = 'drmencryptproperty'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\openxmlencryptproperty'
         {
              ValueName = 'openxmlencryptproperty'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\openxmlencryption'
         {
              ValueName = 'openxmlencryption'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\defaultencryption12'
         {
              ValueName = 'defaultencryption12'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\encryptdocprops'
         {
              ValueName = 'encryptdocprops'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations\allow user locations'
         {
              ValueName = 'allow user locations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\trustcenter\trustbar'
         {
              ValueName = 'trustbar'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\trustcenter'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\osm\enablefileobfuscation'
         {
              ValueName = 'enablefileobfuscation'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\osm'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\wef\trustedcatalogs\requireserververification'
         {
              ValueName = 'requireserververification'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\wef\trustedcatalogs'
              ValueData = 1

         }#>

         <#Registry 'DEL_CU:\software\policies\microsoft\office\common\security\uficontrols'
         {
              ValueName = 'uficontrols'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = ''
              Ensure = 'Absent'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecurity'
         {
              ValueName = 'automationsecurity'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\smart tag\neverloadmanifests'
         {
              ValueName = 'neverloadmanifests'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\smart tag'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\infopath\security\aptca_allowlist'
         {
              ValueName = 'aptca_allowlist'
              ValueType = 'Dword'
              Key = 'HKLM:\software\policies\microsoft\office\15.0\infopath\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\AVGeneral\bFIPSMode'
         {
              ValueName = 'bFIPSMode'
              ValueType = 'Dword'
              Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\AVGeneral'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cAdobeDownload\bLoadSettingsFromURL'
         {
              ValueName = 'bLoadSettingsFromURL'
              ValueType = 'Dword'
              Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cAdobeDownload'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cEUTLDownload\bLoadSettingsFromURL'
         {
              ValueName = 'bLoadSettingsFromURL'
              ValueType = 'Dword'
              Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cEUTLDownload'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 0

         }#>

         Registry 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\common\officeupdate\enableautomaticupdates'
         {
              ValueName = 'enableautomaticupdates'
              ValueType = 'Dword'
              Key = 'HKLM:\software\policies\microsoft\office\15.0\common\officeupdate'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\common\officeupdate\hideenabledisableupdates'
         {
              ValueName = 'hideenabledisableupdates'
              ValueType = 'Dword'
              Key = 'HKLM:\software\policies\microsoft\office\15.0\common\officeupdate'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\PUAProtection'
         {
              ValueName = 'PUAProtection'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\DisableAutoExclusions'
         {
              ValueName = 'DisableAutoExclusions'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning'
         {
              ValueName = 'DisableRemovableDriveScanning'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning'
         {
              ValueName = 'DisableEmailScanning'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\ScheduleDay'
         {
              ValueName = 'ScheduleDay'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ASSignatureDue'
         {
              ValueName = 'ASSignatureDue'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
              ValueData = 7

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\AVSignatureDue'
         {
              ValueName = 'AVSignatureDue'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
              ValueData = 7

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ScheduleDay'
         {
              ValueName = 'ScheduleDay'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\DisableBlockAtFirstSeen'
         {
              ValueName = 'DisableBlockAtFirstSeen'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting'
         {
              ValueName = 'SpynetReporting'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent'
         {
              ValueName = 'SubmitSamplesConsent'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\Threats_ThreatSeverityDefaultAction'
         {
              ValueName = 'Threats_ThreatSeverityDefaultAction'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\5'
         {
              ValueName = '5'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
              ValueData = '2'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\4'
         {
              ValueName = '4'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
              ValueData = '2'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\2'
         {
              ValueName = '2'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
              ValueData = '2'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\1'
         {
              ValueName = '1'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
              ValueData = '2'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules'
         {
              ValueName = 'ExploitGuard_ASR_Rules'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
         {
              ValueName = 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
         {
              ValueName = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\3B576869-A4EC-4529-8536-B80A7769E899'
         {
              ValueName = '3B576869-A4EC-4529-8536-B80A7769E899'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'
         {
              ValueName = '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\D3E037E1-3EB8-44C8-A917-57927947596D'
         {
              ValueName = 'D3E037E1-3EB8-44C8-A917-57927947596D'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'
         {
              ValueName = '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
         {
              ValueName = '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection'
         {
              ValueName = 'EnableNetworkProtection'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
              ValueData = 1

         }

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1

         }#>

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1

         }

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1

         }#>

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1

         }

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1

         }#>

         Registry 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\Comment'
         {
              ValueName = 'Comment'
              ValueType = 'String'
              Key = 'HKLM:\software\microsoft\Office\Common\COM Compatibility'
              ValueData = 'Block all Flash activation'

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024

         }

         <#Registry 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\enablesiphighsecuritymode'
         {
              ValueName = 'enablesiphighsecuritymode'
              ValueType = 'Dword'
              Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\disablehttpconnect'
         {
              ValueName = 'disablehttpconnect'
              ValueType = 'Dword'
              Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
              ValueData = 1

         }#>

         Registry 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueType = 'Dword'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueType = 'Dword'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024

         }

         Registry 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueType = 'Dword'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueType = 'Dword'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024

         }

         Registry 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueType = 'Dword'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueType = 'Dword'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024

         }

         Registry 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueType = 'Dword'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueType = 'Dword'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Adobe\Adobe Acrobat\2015\Installer\DisableMaintenance'
         {
              ValueName = 'DisableMaintenance'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\2015\Installer'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\bEnableFlash'
         {
              ValueName = 'bEnableFlash'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\bProtectedMode'
         {
              ValueName = 'bProtectedMode'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\bDisablePDFHandlerSwitching'
         {
              ValueName = 'bDisablePDFHandlerSwitching'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\bEnhancedSecurityInBrowser'
         {
              ValueName = 'bEnhancedSecurityInBrowser'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\bEnhancedSecurityStandalone'
         {
              ValueName = 'bEnhancedSecurityStandalone'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\bDisableTrustedFolders'
         {
              ValueName = 'bDisableTrustedFolders'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\bDisableTrustedSites'
         {
              ValueName = 'bDisableTrustedSites'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\iProtectedView'
         {
              ValueName = 'iProtectedView'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\iFileAttachmentPerms'
         {
              ValueName = 'iFileAttachmentPerms'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cCloud\bAdobeSendPluginToggle'
         {
              ValueName = 'bAdobeSendPluginToggle'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cCloud'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cCloud\bDisableADCFileStore'
         {
              ValueName = 'bDisableADCFileStore'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cCloud'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cDefaultLaunchURLPerms\iURLPerms'
         {
              ValueName = 'iURLPerms'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cDefaultLaunchURLPerms'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cDefaultLaunchURLPerms\iUnknownURLPerms'
         {
              ValueName = 'iUnknownURLPerms'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cDefaultLaunchURLPerms'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cServices\bTogglePrefsSync'
         {
              ValueName = 'bTogglePrefsSync'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cServices'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cServices\bToggleWebConnectors'
         {
              ValueName = 'bToggleWebConnectors'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cServices'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cSharePoint\bDisableSharePointFeatures'
         {
              ValueName = 'bDisableSharePointFeatures'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cSharePoint'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cWebmailProfiles\bDisableWebmail'
         {
              ValueName = 'bDisableWebmail'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cWebmailProfiles'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cWelcomeScreen\bShowWelcomeScreen'
         {
              ValueName = 'bShowWelcomeScreen'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cWelcomeScreen'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\2015\Installer\DisableMaintenance'
         {
              ValueName = 'DisableMaintenance'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\2015\Installer'
              ValueData = 1

         }

         <#Registry 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPreviewPane'
         {
              ValueName = 'NoPreviewPane'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoReadingPane'
         {
              ValueName = 'NoReadingPane'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\Software\Policies\Microsoft\OneDrive\DisablePersonalSync'
         {
              ValueName = 'DisablePersonalSync'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\OneDrive'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\CloudContent\DisableThirdPartySuggestions'
         {
              ValueName = 'DisableThirdPartySuggestions'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoToastApplicationNotificationOnLockScreen'
         {
              ValueName = 'NoToastApplicationNotificationOnLockScreen'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
              ValueData = 1

         }#>

         Registry 'Registry(POL): HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer\DisableMaintenance'
         {
              ValueName = 'DisableMaintenance'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bEnhancedSecurityStandalone'
         {
              ValueName = 'bEnhancedSecurityStandalone'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bEnhancedSecurityInBrowser'
         {
              ValueName = 'bEnhancedSecurityInBrowser'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\iFileAttachmentPerms'
         {
              ValueName = 'iFileAttachmentPerms'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bEnableFlash'
         {
              ValueName = 'bEnableFlash'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bDisableTrustedFolders'
         {
              ValueName = 'bDisableTrustedFolders'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bProtectedMode'
         {
              ValueName = 'bProtectedMode'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\iProtectedView'
         {
              ValueName = 'iProtectedView'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bDisablePDFHandlerSwitching'
         {
              ValueName = 'bDisablePDFHandlerSwitching'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bDisableTrustedSites'
         {
              ValueName = 'bDisableTrustedSites'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud\bAdobeSendPluginToggle'
         {
              ValueName = 'bAdobeSendPluginToggle'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud\bDisableADCFileStore'
         {
              ValueName = 'bDisableADCFileStore'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms\iUnknownURLPerms'
         {
              ValueName = 'iUnknownURLPerms'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms\iURLPerms'
         {
              ValueName = 'iURLPerms'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices\bTogglePrefsSync'
         {
              ValueName = 'bTogglePrefsSync'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices\bToggleWebConnectors'
         {
              ValueName = 'bToggleWebConnectors'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cSharePoint\bDisableSharePointFeatures'
         {
              ValueName = 'bDisableSharePointFeatures'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cSharePoint'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWebmailProfiles\bDisableWebmail'
         {
              ValueName = 'bDisableWebmail'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWebmailProfiles'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWelcomeScreen\bShowWelcomeScreen'
         {
              ValueName = 'bShowWelcomeScreen'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWelcomeScreen'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer\DisableMaintenance'
         {
              ValueName = 'DisableMaintenance'
              ValueType = 'Dword'
              Key = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'
              ValueData = 1

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\portal\linkpublishingdisabled'
         {
              ValueName = 'linkpublishingdisabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\portal'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\macroruntimescanscope'
         {
              ValueName = 'macroruntimescanscope'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\drmencryptproperty'
         {
              ValueName = 'drmencryptproperty'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\defaultencryption12'
         {
              ValueName = 'defaultencryption12'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\openxmlencryption'
         {
              ValueName = 'openxmlencryption'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations\allow user locations'
         {
              ValueName = 'allow user locations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\access\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\access'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\excel\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\excel'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\infopath\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\infopath'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\outlook\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\outlook'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\powerpoint\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\powerpoint'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\project\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\project'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\publisher\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\publisher'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\visio\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\visio'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\word\noextensibilitycustomizationfromdocument'
         {
              ValueName = 'noextensibilitycustomizationfromdocument'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\word'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\trustcenter\trustbar'
         {
              ValueName = 'trustbar'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\trustcenter'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\internet\donotloadpictures'
         {
              ValueName = 'donotloadpictures'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\internet'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\extractdatadisableui'
         {
              ValueName = 'extractdatadisableui'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\disableautorepublish'
         {
              ValueName = 'disableautorepublish'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\disableautorepublishwarning'
         {
              ValueName = 'disableautorepublishwarning'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions\fupdateext_78_1'
         {
              ValueName = 'fupdateext_78_1'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\extensionhardening'
         {
              ValueName = 'extensionhardening'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\excelbypassencryptedmacroscan'
         {
              ValueName = 'excelbypassencryptedmacroscan'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 0
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\excel\security\excelbypassencryptedmacroscan')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\webservicefunctionwarnings'
         {
              ValueName = 'webservicefunctionwarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 1
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\excel\security\webservicefunctionwarnings')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\disableddeserverlaunch'
         {
              ValueName = 'disableddeserverlaunch'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\disableddeserverlookup'
         {
              ValueName = 'disableddeserverlookup'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\enableblockunsecurequeryfiles'
         {
              ValueName = 'enableblockunsecurequeryfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\dbasefiles'
         {
              ValueName = 'dbasefiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\difandsylkfiles'
         {
              ValueName = 'difandsylkfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl2macros'
         {
              ValueName = 'xl2macros'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl2worksheets'
         {
              ValueName = 'xl2worksheets'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl3macros'
         {
              ValueName = 'xl3macros'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl3worksheets'
         {
              ValueName = 'xl3worksheets'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4macros'
         {
              ValueName = 'xl4macros'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4workbooks'
         {
              ValueName = 'xl4workbooks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4worksheets'
         {
              ValueName = 'xl4worksheets'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl95workbooks'
         {
              ValueName = 'xl95workbooks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl9597workbooksandtemplates'
         {
              ValueName = 'xl9597workbooksandtemplates'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\htmlandxmlssfiles'
         {
              ValueName = 'htmlandxmlssfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\enableonload'
         {
              ValueName = 'enableonload'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = 1
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\openinprotectedview')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\disableeditfrompv'
         {
              ValueName = 'disableeditfrompv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\enabledatabasefileprotectedview'
         {
              ValueName = 'enabledatabasefileprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableinternetfilesinpv'
         {
              ValueName = 'disableinternetfilesinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableunsafelocationsinpv'
         {
              ValueName = 'disableunsafelocationsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\disallowattachmentcustomization'
         {
              ValueName = 'disallowattachmentcustomization'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\general\msgformat'
         {
              ValueName = 'msgformat'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\general'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\junkmailprotection'
         {
              ValueName = 'junkmailprotection'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\internet'
         {
              ValueName = 'internet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\junkmailenablelinks'
         {
              ValueName = 'junkmailenablelinks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\rpc\enablerpcencryption'
         {
              ValueName = 'enablerpcencryption'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\rpc'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\authenticationservice'
         {
              ValueName = 'authenticationservice'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 16

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\publicfolderscript'
         {
              ValueName = 'publicfolderscript'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\sharedfolderscript'
         {
              ValueName = 'sharedfolderscript'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\allowactivexoneoffforms'
         {
              ValueName = 'allowactivexoneoffforms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\publishtogaldisabled'
         {
              ValueName = 'publishtogaldisabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\minenckey'
         {
              ValueName = 'minenckey'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 168

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\warnaboutinvalid'
         {
              ValueName = 'warnaboutinvalid'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\usecrlchasing'
         {
              ValueName = 'usecrlchasing'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\adminsecuritymode'
         {
              ValueName = 'adminsecuritymode'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\allowuserstolowerattachments'
         {
              ValueName = 'allowuserstolowerattachments'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\showlevel1attach'
         {
              ValueName = 'showlevel1attach'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel1'
         {
              ValueName = 'fileextensionsremovelevel1'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = ''
              Ensure = 'Absent'

         }#>

         <#Registry 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel2'
         {
              ValueName = 'fileextensionsremovelevel2'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = ''
              Ensure = 'Absent'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\enableoneoffformscripts'
         {
              ValueName = 'enableoneoffformscripts'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomcustomaction'
         {
              ValueName = 'promptoomcustomaction'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressbookaccess'
         {
              ValueName = 'promptoomaddressbookaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomformulaaccess'
         {
              ValueName = 'promptoomformulaaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsaveas'
         {
              ValueName = 'promptoomsaveas'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressinformationaccess'
         {
              ValueName = 'promptoomaddressinformationaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoommeetingtaskrequestresponse'
         {
              ValueName = 'promptoommeetingtaskrequestresponse'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsend'
         {
              ValueName = 'promptoomsend'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\level'
         {
              ValueName = 'level'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\runprograms'
         {
              ValueName = 'runprograms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 0
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\runprograms')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\powerpointbypassencryptedmacroscan'
         {
              ValueName = 'powerpointbypassencryptedmacroscan'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 0
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\powerpointbypassencryptedmacroscan')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock\binaryfiles'
         {
              ValueName = 'binaryfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\enableonload'
         {
              ValueName = 'enableonload'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = 1
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\openinprotectedview')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\disableeditfrompv'
         {
              ValueName = 'disableeditfrompv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableinternetfilesinpv'
         {
              ValueName = 'disableinternetfilesinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableunsafelocationsinpv'
         {
              ValueName = 'disableunsafelocationsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio2000files'
         {
              ValueName = 'visio2000files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio2003files'
         {
              ValueName = 'visio2003files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio50andearlierfiles'
         {
              ValueName = 'visio50andearlierfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\wordbypassencryptedmacroscan'
         {
              ValueName = 'wordbypassencryptedmacroscan'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 0
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\word\security\wordbypassencryptedmacroscan')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2files'
         {
              ValueName = 'word2files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2000files'
         {
              ValueName = 'word2000files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2003files'
         {
              ValueName = 'word2003files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2007files'
         {
              ValueName = 'word2007files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word60files'
         {
              ValueName = 'word60files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word95files'
         {
              ValueName = 'word95files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word97files'
         {
              ValueName = 'word97files'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\wordxpfiles'
         {
              ValueName = 'wordxpfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = 1
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\16.0\word\security\filevalidation\openinprotectedview')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\disableeditfrompv'
         {
              ValueName = 'disableeditfrompv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\enableonload'
         {
              ValueName = 'enableonload'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableinternetfilesinpv'
         {
              ValueName = 'disableinternetfilesinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableunsafelocationsinpv'
         {
              ValueName = 'disableunsafelocationsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\uficontrols'
         {
              ValueName = 'uficontrols'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 6
              DependsOn = @('[Registry]DEL_CU:\software\policies\microsoft\office\common\security\uficontrols')

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecurity'
         {
              ValueName = 'automationsecurity'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecuritypublisher'
         {
              ValueName = 'automationsecuritypublisher'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\common\smart tag\neverloadmanifests'
         {
              ValueName = 'neverloadmanifests'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\smart tag'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\vba\security\loadcontrolsinforms'
         {
              ValueName = 'loadcontrolsinforms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\vba\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\internet\donotunderlinehyperlinks'
         {
              ValueName = 'donotunderlinehyperlinks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\internet'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\security\modaltrustdecisiononly'
         {
              ValueName = 'modaltrustdecisiononly'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\settings\default file format'
         {
              ValueName = 'default file format'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\settings'
              ValueData = 12

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\settings\noconvertdialog'
         {
              ValueName = 'noconvertdialog'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\settings'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\mailsettings\disablesignatures'
         {
              ValueName = 'disablesignatures'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\mailsettings'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\mailsettings\plainwraplen'
         {
              ValueName = 'plainwraplen'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\mailsettings'
              ValueData = 132

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\meetings\profile\serverui'
         {
              ValueName = 'serverui'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\meetings\profile'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\disableantispam'
         {
              ValueName = 'disableantispam'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\disallowattachmentcustomization'
         {
              ValueName = 'disallowattachmentcustomization'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\autoformat\pgrfafo_25_1'
         {
              ValueName = 'pgrfafo_25_1'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\autoformat'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\calendar\disableweather'
         {
              ValueName = 'disableweather'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\calendar'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\general\check default client'
         {
              ValueName = 'check default client'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\general'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\general\msgformat'
         {
              ValueName = 'msgformat'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\general'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\unblocksafezone'
         {
              ValueName = 'unblocksafezone'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\junkmailtrustoutgoingrecipients'
         {
              ValueName = 'junkmailtrustoutgoingrecipients'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\trustedzone'
         {
              ValueName = 'trustedzone'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\junkmailenablelinks'
         {
              ValueName = 'junkmailenablelinks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\internet'
         {
              ValueName = 'internet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\intranet'
         {
              ValueName = 'intranet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\blockextcontent'
         {
              ValueName = 'blockextcontent'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\unblockspecificsenders'
         {
              ValueName = 'unblockspecificsenders'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\message plain format mime'
         {
              ValueName = 'message plain format mime'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\readasplain'
         {
              ValueName = 'readasplain'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\readsignedasplain'
         {
              ValueName = 'readsignedasplain'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\junkmailtrustcontacts'
         {
              ValueName = 'junkmailtrustcontacts'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\message rtf format'
         {
              ValueName = 'message rtf format'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\editorpreference'
         {
              ValueName = 'editorpreference'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueData = 65536

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal\restrictedaccessonly'
         {
              ValueName = 'restrictedaccessonly'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal\disabledav'
         {
              ValueName = 'disabledav'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal\disableofficeonline'
         {
              ValueName = 'disableofficeonline'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal\publishcalendardetailspolicy'
         {
              ValueName = 'publishcalendardetailspolicy'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal'
              ValueData = 16384

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal\singleuploadonly'
         {
              ValueName = 'singleuploadonly'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss\enablefulltexthtml'
         {
              ValueName = 'enablefulltexthtml'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss\synctosyscfl'
         {
              ValueName = 'synctosyscfl'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss\disable'
         {
              ValueName = 'disable'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss\enableattachments'
         {
              ValueName = 'enableattachments'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\webcal\disable'
         {
              ValueName = 'disable'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\webcal'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\webcal\enableattachments'
         {
              ValueName = 'enableattachments'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\webcal'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\rpc\enablerpcencryption'
         {
              ValueName = 'enablerpcencryption'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\rpc'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\allowactivexoneoffforms'
         {
              ValueName = 'allowactivexoneoffforms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\enableoneoffformscripts'
         {
              ValueName = 'enableoneoffformscripts'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\addintrust'
         {
              ValueName = 'addintrust'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoomaddressbookaccess'
         {
              ValueName = 'promptoomaddressbookaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\allowuserstolowerattachments'
         {
              ValueName = 'allowuserstolowerattachments'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoomformulaaccess'
         {
              ValueName = 'promptoomformulaaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoomsaveas'
         {
              ValueName = 'promptoomsaveas'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoomaddressinformationaccess'
         {
              ValueName = 'promptoomaddressinformationaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoommeetingtaskrequestresponse'
         {
              ValueName = 'promptoommeetingtaskrequestresponse'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoomsend'
         {
              ValueName = 'promptoomsend'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\enablerememberpwd'
         {
              ValueName = 'enablerememberpwd'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\dontpromptlevel1attachclose'
         {
              ValueName = 'dontpromptlevel1attachclose'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\dontpromptlevel1attachsend'
         {
              ValueName = 'dontpromptlevel1attachsend'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\showlevel1attach'
         {
              ValueName = 'showlevel1attach'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\nondefaultstorescript'
         {
              ValueName = 'nondefaultstorescript'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\publicfolderscript'
         {
              ValueName = 'publicfolderscript'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\sharedfolderscript'
         {
              ValueName = 'sharedfolderscript'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         Registry 'DEL_CU:\software\policies\microsoft\office\15.0\outlook\security\outlooksecuretempfolder'
         {
              ValueName = 'outlooksecuretempfolder'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = ''
              Ensure = 'Absent'

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\authenticationservice'
         {
              ValueName = 'authenticationservice'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 9

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\msgformats'
         {
              ValueName = 'msgformats'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\sigstatusnotrustdecision'
         {
              ValueName = 'sigstatusnotrustdecision'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\adminsecuritymode'
         {
              ValueName = 'adminsecuritymode'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 3

         }#>

         Registry 'DEL_CU:\software\policies\microsoft\office\15.0\outlook\security\fileextensionsremovelevel1'
         {
              ValueName = 'fileextensionsremovelevel1'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = ''
              Ensure = 'Absent'

         }

         Registry 'DEL_CU:\software\policies\microsoft\office\15.0\outlook\security\fileextensionsremovelevel2'
         {
              ValueName = 'fileextensionsremovelevel2'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = ''
              Ensure = 'Absent'

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\usecrlchasing'
         {
              ValueName = 'usecrlchasing'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\fipsmode'
         {
              ValueName = 'fipsmode'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\externalsmime'
         {
              ValueName = 'externalsmime'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\respondtoreceiptrequests'
         {
              ValueName = 'respondtoreceiptrequests'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\level'
         {
              ValueName = 'level'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\clearsign'
         {
              ValueName = 'clearsign'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoomcustomaction'
         {
              ValueName = 'promptoomcustomaction'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\warnaboutinvalid'
         {
              ValueName = 'warnaboutinvalid'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\forcedefaultprofile'
         {
              ValueName = 'forcedefaultprofile'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\minenckey'
         {
              ValueName = 'minenckey'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 168

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\nocheckonsessionsecurity'
         {
              ValueName = 'nocheckonsessionsecurity'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\supressnamechecks'
         {
              ValueName = 'supressnamechecks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'DELVALS_CU:\software\policies\microsoft\office\15.0\outlook\security\trustedaddins'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security\trustedaddins'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\meetings\profile\serverui'
         {
              ValueName = 'serverui'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\meetings\profile'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\disallowattachmentcustomization'
         {
              ValueName = 'disallowattachmentcustomization'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\blockextcontent'
         {
              ValueName = 'blockextcontent'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\unblockspecificsenders'
         {
              ValueName = 'unblockspecificsenders'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\unblocksafezone'
         {
              ValueName = 'unblocksafezone'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\trustedzone'
         {
              ValueName = 'trustedzone'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\internet'
         {
              ValueName = 'internet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\intranet'
         {
              ValueName = 'intranet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\junkmailenablelinks'
         {
              ValueName = 'junkmailenablelinks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\disableofficeonline'
         {
              ValueName = 'disableofficeonline'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\disabledav'
         {
              ValueName = 'disabledav'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\publishcalendardetailspolicy'
         {
              ValueName = 'publishcalendardetailspolicy'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
              ValueData = 16384

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\restrictedaccessonly'
         {
              ValueName = 'restrictedaccessonly'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss\enablefulltexthtml'
         {
              ValueName = 'enablefulltexthtml'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss\enableattachments'
         {
              ValueName = 'enableattachments'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal\enableattachments'
         {
              ValueName = 'enableattachments'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal\disable'
         {
              ValueName = 'disable'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\rpc\enablerpcencryption'
         {
              ValueName = 'enablerpcencryption'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\rpc'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\sharedfolderscript'
         {
              ValueName = 'sharedfolderscript'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\publicfolderscript'
         {
              ValueName = 'publicfolderscript'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\allowactivexoneoffforms'
         {
              ValueName = 'allowactivexoneoffforms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\addintrust'
         {
              ValueName = 'addintrust'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\enablerememberpwd'
         {
              ValueName = 'enablerememberpwd'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\adminsecuritymode'
         {
              ValueName = 'adminsecuritymode'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\showlevel1attach'
         {
              ValueName = 'showlevel1attach'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel1'
         {
              ValueName = 'fileextensionsremovelevel1'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = ''
              Ensure = 'Absent'

         }#>

         <#Registry 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel2'
         {
              ValueName = 'fileextensionsremovelevel2'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = ''
              Ensure = 'Absent'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\enableoneoffformscripts'
         {
              ValueName = 'enableoneoffformscripts'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomcustomaction'
         {
              ValueName = 'promptoomcustomaction'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsend'
         {
              ValueName = 'promptoomsend'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressbookaccess'
         {
              ValueName = 'promptoomaddressbookaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoommeetingtaskrequestresponse'
         {
              ValueName = 'promptoommeetingtaskrequestresponse'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsaveas'
         {
              ValueName = 'promptoomsaveas'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomformulaaccess'
         {
              ValueName = 'promptoomformulaaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\externalsmime'
         {
              ValueName = 'externalsmime'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressinformationaccess'
         {
              ValueName = 'promptoomaddressinformationaccess'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\msgformats'
         {
              ValueName = 'msgformats'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\fipsmode'
         {
              ValueName = 'fipsmode'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\clearsign'
         {
              ValueName = 'clearsign'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\respondtoreceiptrequests'
         {
              ValueName = 'respondtoreceiptrequests'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\usecrlchasing'
         {
              ValueName = 'usecrlchasing'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\level'
         {
              ValueName = 'level'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 3

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\authenticationservice'
         {
              ValueName = 'authenticationservice'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 16

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\forcedefaultprofile'
         {
              ValueName = 'forcedefaultprofile'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\minenckey'
         {
              ValueName = 'minenckey'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 168

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\nocheckonsessionsecurity'
         {
              ValueName = 'nocheckonsessionsecurity'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\supressnamechecks'
         {
              ValueName = 'supressnamechecks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1

         }#>

         <#Registry 'DELVALS_CU:\software\policies\microsoft\office\16.0\outlook\security\trustedaddins'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security\trustedaddins'

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\trustwss'
         {
              ValueName = 'trustwss'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\visio\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\visio\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\visio\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\visio\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\visio\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\visio\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\internet\donotloadpictures'
         {
              ValueName = 'donotloadpictures'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\internet'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\defaultformat'
         {
              ValueName = 'defaultformat'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options'
              ValueData = 51

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\autohyperlink'
         {
              ValueName = 'autohyperlink'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\disableautorepublish'
         {
              ValueName = 'disableautorepublish'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\disableautorepublishwarning'
         {
              ValueName = 'disableautorepublishwarning'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\extractdatadisableui'
         {
              ValueName = 'extractdatadisableui'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\binaryoptions\fupdateext_78_1'
         {
              ValueName = 'fupdateext_78_1'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options\binaryoptions'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\binaryoptions\fglobalsheet_37_1'
         {
              ValueName = 'fglobalsheet_37_1'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options\binaryoptions'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\excelbypassencryptedmacroscan'
         {
              ValueName = 'excelbypassencryptedmacroscan'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\accessvbom'
         {
              ValueName = 'accessvbom'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\extensionhardening'
         {
              ValueName = 'extensionhardening'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\webservicefunctionwarnings'
         {
              ValueName = 'webservicefunctionwarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\excel12betafilesfromconverters'
         {
              ValueName = 'excel12betafilesfromconverters'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\dbasefiles'
         {
              ValueName = 'dbasefiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\difandsylkfiles'
         {
              ValueName = 'difandsylkfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl2macros'
         {
              ValueName = 'xl2macros'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl2worksheets'
         {
              ValueName = 'xl2worksheets'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl3macros'
         {
              ValueName = 'xl3macros'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl3worksheets'
         {
              ValueName = 'xl3worksheets'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl4macros'
         {
              ValueName = 'xl4macros'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl4workbooks'
         {
              ValueName = 'xl4workbooks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl4worksheets'
         {
              ValueName = 'xl4worksheets'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl95workbooks'
         {
              ValueName = 'xl95workbooks'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 5

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl9597workbooksandtemplates'
         {
              ValueName = 'xl9597workbooksandtemplates'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 5

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\htmlandxmlssfiles'
         {
              ValueName = 'htmlandxmlssfiles'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\filevalidation\enableonload'
         {
              ValueName = 'enableonload'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\filevalidation\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\filevalidation\disableeditfrompv'
         {
              ValueName = 'disableeditfrompv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\protectedview\disableinternetfilesinpv'
         {
              ValueName = 'disableinternetfilesinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\protectedview\disableunsafelocationsinpv'
         {
              ValueName = 'disableunsafelocationsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\trusted locations\alllocationsdisabled'
         {
              ValueName = 'alllocationsdisabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\trusted locations'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\trusted locations'
              ValueData = 0

         }#>

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\RemoteAccessHostFirewallTraversal'
         {
              ValueName = 'RemoteAccessHostFirewallTraversal'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultNotificationsSetting'
         {
              ValueName = 'DefaultNotificationsSetting'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultPopupsSetting'
         {
              ValueName = 'DefaultPopupsSetting'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultGeolocationSetting'
         {
              ValueName = 'DefaultGeolocationSetting'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderName'
         {
              ValueName = 'DefaultSearchProviderName'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 'Google Encrypted'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderSearchURL'
         {
              ValueName = 'DefaultSearchProviderSearchURL'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 'https://www.google.com/#q={searchTerms}'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderEnabled'
         {
              ValueName = 'DefaultSearchProviderEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PasswordManagerEnabled'
         {
              ValueName = 'PasswordManagerEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AllowOutdatedPlugins'
         {
              ValueName = 'AllowOutdatedPlugins'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\BlockThirdPartyCookies'
         {
              ValueName = 'BlockThirdPartyCookies'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\BackgroundModeEnabled'
         {
              ValueName = 'BackgroundModeEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SyncDisabled'
         {
              ValueName = 'SyncDisabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\CloudPrintProxyEnabled'
         {
              ValueName = 'CloudPrintProxyEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\MetricsReportingEnabled'
         {
              ValueName = 'MetricsReportingEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SearchSuggestEnabled'
         {
              ValueName = 'SearchSuggestEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ImportSavedPasswords'
         {
              ValueName = 'ImportSavedPasswords'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\IncognitoModeAvailability'
         {
              ValueName = 'IncognitoModeAvailability'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\EnableOnlineRevocationChecks'
         {
              ValueName = 'EnableOnlineRevocationChecks'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SafeBrowsingEnabled'
         {
              ValueName = 'SafeBrowsingEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SavingBrowserHistoryDisabled'
         {
              ValueName = 'SavingBrowserHistoryDisabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultPluginsSetting'
         {
              ValueName = 'DefaultPluginsSetting'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 3

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AllowDeletingBrowserHistory'
         {
              ValueName = 'AllowDeletingBrowserHistory'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PromptForDownloadLocation'
         {
              ValueName = 'PromptForDownloadLocation'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 1

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DownloadRestrictions'
         {
              ValueName = 'DownloadRestrictions'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowed'
         {
              ValueName = 'AutoplayAllowed'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SafeBrowsingExtendedReportingEnabled'
         {
              ValueName = 'SafeBrowsingExtendedReportingEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultWebUsbGuardSetting'
         {
              ValueName = 'DefaultWebUsbGuardSetting'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ChromeCleanupEnabled'
         {
              ValueName = 'ChromeCleanupEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ChromeCleanupReportingEnabled'
         {
              ValueName = 'ChromeCleanupReportingEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\EnableMediaRouter'
         {
              ValueName = 'EnableMediaRouter'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SSLVersionMin'
         {
              ValueName = 'SSLVersionMin'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 'tls1.1'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\UrlKeyedAnonymizedDataCollectionEnabled'
         {
              ValueName = 'UrlKeyedAnonymizedDataCollectionEnabled'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\WebRtcEventLogCollectionAllowed'
         {
              ValueName = 'WebRtcEventLogCollectionAllowed'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 0

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\NetworkPredictionOptions'
         {
              ValueName = 'NetworkPredictionOptions'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 2

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DeveloperToolsAvailability'
         {
              ValueName = 'DeveloperToolsAvailability'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
              ValueData = 2

         }

         <#Registry 'DELVALS_\Software\Policies\Google\Chrome\AutoplayWhitelist'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome\AutoplayWhitelist'

         }#>

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayWhitelist\1'
         {
              ValueName = '1'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome\AutoplayWhitelist'
              ValueData = '[*.]mil'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayWhitelist\2'
         {
              ValueName = '2'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome\AutoplayWhitelist'
              ValueData = '[*.]gov'

         }

         <#Registry 'DELVALS_\Software\Policies\Google\Chrome\CookiesSessionOnlyForUrls'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome\CookiesSessionOnlyForUrls'

         }#>

         <#Registry 'DELVALS_\Software\Policies\Google\Chrome\ExtensionInstallBlacklist'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlacklist'

         }#>

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlacklist\1'
         {
              ValueName = '1'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlacklist'
              ValueData = '*'

         }

         <#Registry 'DELVALS_\Software\Policies\Google\Chrome\ExtensionInstallWhitelist'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome\ExtensionInstallWhitelist'

         }#>

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ExtensionInstallWhitelist\1'
         {
              ValueName = '1'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome\ExtensionInstallWhitelist'
              ValueData = 'oiigbmnaadbkfbmpbfijlflahbdbdgdf'

         }

         <#Registry 'DELVALS_\Software\Policies\Google\Chrome\PluginsAllowedForUrls'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome\PluginsAllowedForUrls'

         }#>

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PluginsAllowedForUrls\1'
         {
              ValueName = '1'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome\PluginsAllowedForUrls'
              ValueData = '[*.]mil'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PluginsAllowedForUrls\2'
         {
              ValueName = '2'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome\PluginsAllowedForUrls'
              ValueData = '[*.]gov'

         }

         <#Registry 'DELVALS_\Software\Policies\Google\Chrome\URLBlacklist'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome\URLBlacklist'

         }#>

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\URLBlacklist\1'
         {
              ValueName = '1'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Google\Chrome\URLBlacklist'
              ValueData = 'javascript://*'

         }

         Registry 'Registry(POL): HKLM:\Software\Policies\Google\Update\AutoUpdateCheckPeriodMinutes'
         {
              ValueName = 'AutoUpdateCheckPeriodMinutes'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Policies\Google\Update'
              ValueData = 10080

         }

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\options\defaultformat'
         {
              ValueName = 'defaultformat'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\options'
              ValueData = 27

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\options\markupopensave'
         {
              ValueName = 'markupopensave'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\options'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\notbpromptunsignedaddin'
         {
              ValueName = 'notbpromptunsignedaddin'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\powerpointbypassencryptedmacroscan'
         {
              ValueName = 'powerpointbypassencryptedmacroscan'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\accessvbom'
         {
              ValueName = 'accessvbom'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueData = 2

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\runprograms'
         {
              ValueName = 'runprograms'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\downloadimages'
         {
              ValueName = 'downloadimages'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\requireaddinsig'
         {
              ValueName = 'requireaddinsig'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\fileblock\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\fileblock'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\fileblock\powerpoint12betafilesfromconverters'
         {
              ValueName = 'powerpoint12betafilesfromconverters'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\fileblock'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation\enableonload'
         {
              ValueName = 'enableonload'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation\openinprotectedview'
         {
              ValueName = 'openinprotectedview'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation\disableeditfrompv'
         {
              ValueName = 'disableeditfrompv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\protectedview\disableinternetfilesinpv'
         {
              ValueName = 'disableinternetfilesinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\protectedview\disableunsafelocationsinpv'
         {
              ValueName = 'disableunsafelocationsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\protectedview'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\trusted locations\alllocationsdisabled'
         {
              ValueName = 'alllocationsdisabled'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\trusted locations'
              ValueData = 1

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\trusted locations\allownetworklocations'
         {
              ValueName = 'allownetworklocations'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\trusted locations'
              ValueData = 0

         }#>

         <#Registry 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\slide libraries\disableslideupdate'
         {
              ValueName = 'disableslideupdate'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\slide libraries'
              ValueData = 1

         }#>

         AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
         {
              Name = 'Credential Validation'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
         {
              Name = 'Credential Validation'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
         {
              Name = 'Security Group Management'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
         {
              Name = 'Security Group Management'
              Ensure = 'Absent'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
         {
              Name = 'User Account Management'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
         {
              Name = 'User Account Management'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
         {
              Name = 'Plug and Play Events'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
         {
              Name = 'Plug and Play Events'
              Ensure = 'Absent'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
         {
              Name = 'Process Creation'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
         {
              Name = 'Process Creation'
              Ensure = 'Absent'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
         {
              Name = 'Account Lockout'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

          AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
         {
              Name = 'Account Lockout'
              Ensure = 'Absent'
              AuditFlag = 'Success'

         }

         AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
         {
              Name = 'Group Membership'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
         {
              Name = 'Group Membership'
              Ensure = 'Absent'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
         {
              Name = 'Logoff'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
         {
              Name = 'Logoff'
              Ensure = 'Absent'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
         {
              Name = 'Logon'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
         {
              Name = 'Logon'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success) - Inclusion'
         {
              Name = 'Other Logon/Logoff Events'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure) - Inclusion'
         {
              Name = 'Other Logon/Logoff Events'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
         {
              Name = 'Special Logon'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
         {
              Name = 'Special Logon'
              Ensure = 'Absent'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Detailed File Share (Failure) - Inclusion'
         {
              Name = 'Detailed File Share'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

          AuditPolicySubcategory 'Audit Detailed File Share (Success) - Inclusion'
         {
              Name = 'Detailed File Share'
              Ensure = 'Absent'
              AuditFlag = 'Success'

         }

         AuditPolicySubcategory 'Audit File Share (Success) - Inclusion'
         {
              Name = 'File Share'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit File Share (Failure) - Inclusion'
         {
              Name = 'File Share'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
         {
              Name = 'Other Object Access Events'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
         {
              Name = 'Other Object Access Events'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
         {
              Name = 'Removable Storage'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
         {
              Name = 'Removable Storage'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
         {
              Name = 'Audit Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
         {
              Name = 'Audit Policy Change'
              Ensure = 'Absent'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
         {
              Name = 'Authentication Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
         {
              Name = 'Authentication Policy Change'
              Ensure = 'Absent'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
         {
              Name = 'Authorization Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
         {
              Name = 'Authorization Policy Change'
              Ensure = 'Absent'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success) - Inclusion'
         {
              Name = 'MPSSVC Rule-Level Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure) - Inclusion'
         {
              Name = 'MPSSVC Rule-Level Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Other Policy Change Events (Success) - Inclusion'
         {
              Name = 'Other Policy Change Events'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Other Policy Change Events (Failure) - Inclusion'
         {
              Name = 'Other Policy Change Events'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
         {
              Name = 'Sensitive Privilege Use'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
         {
              Name = 'Sensitive Privilege Use'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
         {
              Name = 'IPsec Driver'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

          AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
         {
              Name = 'IPsec Driver'
              Ensure = 'Absent'
              AuditFlag = 'Success'

         }

         AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
         {
              Name = 'Other System Events'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
         {
              Name = 'Other System Events'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
         {
              Name = 'Security State Change'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
         {
              Name = 'Security State Change'
              Ensure = 'Absent'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
         {
              Name = 'Security System Extension'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
         {
              Name = 'Security System Extension'
              Ensure = 'Absent'
              AuditFlag = 'Failure'

         }

         AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
         {
              Name = 'System Integrity'
              Ensure = 'Present'
              AuditFlag = 'Success'

         }

          AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
         {
              Name = 'System Integrity'
              Ensure = 'Present'
              AuditFlag = 'Failure'

         }

         Service 'Services(INF): AppIDSvc'
         {
              Name = 'AppIDSvc'
              State = 'Running'

         }

         Service 'Services(INF): seclogon'
         {
              Name = 'seclogon'
              State = 'Stopped'

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
         {
              Policy = 'Load_and_unload_device_drivers'
              Force = $True
              Identity = @('*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
         {
              Policy = 'Impersonate_a_client_after_authentication'
              Force = $True
              Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
         {
              Policy = 'Take_ownership_of_files_or_other_objects'
              Force = $True
              Identity = @('*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
         {
              Policy = 'Deny_log_on_locally'
              Force = $True
              Identity = @('*S-1-5-32-546')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
         {
              Policy = 'Deny_log_on_as_a_batch_job'
              Force = $True
              Identity = @('')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
         {
              Policy = 'Back_up_files_and_directories'
              Force = $True
              Identity = @('*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
         {
              Policy = 'Access_Credential_Manager_as_a_trusted_caller'
              Force = $True
              Identity = @('')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
         {
              Policy = 'Create_symbolic_links'
              Force = $True
              Identity = @('*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Change_the_system_time'
         {
              Policy = 'Change_the_system_time'
              Force = $True
              Identity = @('*S-1-5-19', '*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
         {
              Policy = 'Debug_programs'
              Force = $True
              Identity = @('*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
         {
              Policy = 'Deny_log_on_through_Remote_Desktop_Services'
              Force = $True
              Identity = @('*S-1-5-113', '*S-1-5-32-546')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
         {
              Policy = 'Lock_pages_in_memory'
              Force = $True
              Identity = @('')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
         {
              Policy = 'Manage_auditing_and_security_log'
              Force = $True
              Identity = @('*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
         {
              Policy = 'Allow_log_on_locally'
              Force = $True
              Identity = @('*S-1-5-32-545', '*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
         {
              Policy = 'Create_a_pagefile'
              Force = $True
              Identity = @('*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
         {
              Policy = 'Restore_files_and_directories'
              Force = $True
              Identity = @('*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
         {
              Policy = 'Create_a_token_object'
              Force = $True
              Identity = @('')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
         {
              Policy = 'Create_permanent_shared_objects'
              Force = $True
              Identity = @('')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
         {
              Policy = 'Create_global_objects'
              Force = $True
              Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
         {
              Policy = 'Deny_log_on_as_a_service'
              Force = $True
              Identity = @('')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
         {
              Policy = 'Deny_access_to_this_computer_from_the_network'
              Force = $True
              Identity = @('*S-1-5-113', '*S-1-5-32-546')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
         {
              Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
              Force = $True
              Identity = @('')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
         {
              Policy = 'Force_shutdown_from_a_remote_system'
              Force = $True
              Identity = @('*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
         {
              Policy = 'Access_this_computer_from_the_network'
              Force = $True
              Identity = @('*S-1-5-32-555', '*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
         {
              Policy = 'Perform_volume_maintenance_tasks'
              Force = $True
              Identity = @('*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
         {
              Policy = 'Act_as_part_of_the_operating_system'
              Force = $True
              Identity = @('')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
         {
              Policy = 'Profile_single_process'
              Force = $True
              Identity = @('*S-1-5-32-544')

         }

         UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
         {
              Policy = 'Modify_firmware_environment_values'
              Force = $True
              Identity = @('*S-1-5-32-544')

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword'
         {
              ValueName = 'EnablePlainTextPassword'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
              ValueData = 0

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal'
         {
              ValueName = 'RequireSignOrSeal'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption'
         {
              ValueName = 'ScRemoveOption'
              ValueType = 'String'
              Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
              ValueData = '1'

         }

         Registry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection'
         {
              ValueName = 'EnableInstallerDetection'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange'
         {
              ValueName = 'DisablePasswordChange'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
              ValueData = 0

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Session Manager\ProtectionMode'
         {
              ValueName = 'ProtectionMode'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths'
         {
              ValueName = 'EnableSecureUIAPaths'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM'
         {
              ValueName = 'RestrictAnonymousSAM'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback'
         {
              ValueName = 'allownullsessionfallback'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
              ValueData = 0

         }

         Registry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser'
         {
              ValueName = 'ConsentPromptBehaviorUser'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 0

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\RestrictAnonymous'
         {
              ValueName = 'RestrictAnonymous'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID'
         {
              ValueName = 'AllowOnlineID'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\pku2u'
              ValueData = 0

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature'
         {
              ValueName = 'RequireSecuritySignature'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\NoLMHash'
         {
              ValueName = 'NoLMHash'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
         {
              ValueName = 'LmCompatibilityLevel'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
              ValueData = 5

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel'
         {
              ValueName = 'SealSecureChannel'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM'
         {
              ValueName = 'RestrictRemoteSAM'
              ValueType = 'String'
              Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
              ValueData = 'O:BAG:BAD:(A;;RC;;;BA)'

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec'
         {
              ValueName = 'NTLMMinClientSec'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
              ValueData = 537395200

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy'
         {
              ValueName = 'SCENoApplyLegacyAuditPolicy'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin'
         {
              ValueName = 'ConsentPromptBehaviorAdmin'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 2

         }

         Registry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs'
         {
              ValueName = 'InactivityTimeoutSecs'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 900

         }

         Registry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes'
         {
              ValueName = 'SupportedEncryptionTypes'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
              ValueData = 2147483640

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'
         {
              ValueName = 'RequireSecuritySignature'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey'
         {
              ValueName = 'RequireStrongKey'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess'
         {
              ValueName = 'RestrictNullSessAccess'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous'
         {
              ValueName = 'EveryoneIncludesAnonymous'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
              ValueData = 0

         }

         Registry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization'
         {
              ValueName = 'EnableVirtualization'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity'
         {
              ValueName = 'LDAPClientIntegrity'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\LDAP'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge'
         {
              ValueName = 'MaximumPasswordAge'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
              ValueData = 30

         }

         Registry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA'
         {
              ValueName = 'EnableLUA'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled'
         {
              ValueName = 'Enabled'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse'
         {
              ValueName = 'LimitBlankPasswordUse'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken'
         {
              ValueName = 'FilterAdministratorToken'
              ValueType = 'Dword'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount'
         {
              ValueName = 'CachedLogonsCount'
              ValueType = 'String'
              Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
              ValueData = '10'

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel'
         {
              ValueName = 'SignSecureChannel'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
              ValueData = 1

         }

         Registry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec'
         {
              ValueName = 'NTLMMinServerSec'
              ValueType = 'Dword'
              Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
              ValueData = 537395200

         }

         SecurityOption 'SecuritySetting(INF): NewGuestName'
         {
              Accounts_Rename_guest_account = 'Z_Visitor'
              Name = 'Accounts_Rename_guest_account'

         }

         AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
         {
              Name = 'Enforce_password_history'
              Enforce_password_history = 24

         }

         AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
         {
              Name = 'Minimum_Password_Length'
              Minimum_Password_Length = 14

         }

         AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
         {
              Minimum_Password_Age = 1
              Name = 'Minimum_Password_Age'

         }

         SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
         {
              Name = 'Network_access_Allow_anonymous_SID_Name_translation'
              Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'

         }

         SecurityOption 'SecuritySetting(INF): EnableAdminAccount'
         {
              Name = 'Accounts_Administrator_account_status'
              Accounts_Administrator_account_status = 'Disabled'

         }

         AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
         {
              Reset_account_lockout_counter_after = 15
              Name = 'Reset_account_lockout_counter_after'

         }

         AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
         {
              Name = 'Maximum_Password_Age'
              Maximum_Password_Age = 60

         }

         AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
         {
              Name = 'Store_passwords_using_reversible_encryption'
              Store_passwords_using_reversible_encryption = 'Disabled'

         }

         AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
         {
              Name = 'Account_lockout_threshold'
              Account_lockout_threshold = 3

         }

         AccountPolicy 'SecuritySetting(INF): LockoutDuration'
         {
              Name = 'Account_lockout_duration'
              Account_lockout_duration = 15

         }

         SecurityOption 'SecuritySetting(INF): NewAdministratorName'
         {
              Accounts_Rename_administrator_account = 'Z_Admin'
              Name = 'Accounts_Rename_administrator_account'

         }

         SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
         {
              Accounts_Guest_account_status = 'Disabled'
              Name = 'Accounts_Guest_account_status'

         }

         AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
         {
              Name = 'Password_must_meet_complexity_requirements'
              Password_must_meet_complexity_requirements = 'Enabled'

         }

         <#Service 'Services(INF): AppIDSvc'
         {
              Name = 'AppIDSvc'
              State = 'Running'

         }#>

	}
}
DSCFromGPO -OutputPath 'C:\Users\smiller\Documents\GitHub\W10-Optimize-and-Harden\Files\DSC\Output'
