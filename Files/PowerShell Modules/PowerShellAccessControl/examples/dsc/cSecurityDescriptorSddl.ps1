# Needed for ServiceAccessRights enumeration
Import-Module PowerShellAccessControl

Configuration TestSecurityDescriptorSddlResource {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    $TestFolderOwner = "C:\powershell\deleteme\dsc_test_sddl_owner"
    $TestFolderSacl = "C:\powershell\deleteme\dsc_test_sddl_sacl"
    $TestFolderDacl = "C:\powershell\deleteme\dsc_test_sddl_dacl"
    $TestKey = "HKLM:\SOFTWARE\Dsc_Test_sddl"

    Node $ComputerName {

        File TestFolderOwner {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $TestFolderOwner
        }

        File TestFolderSacl {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $TestFolderSacl
        }

        File TestFolderDacl {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $TestFolderDacl
        }

        cSecurityDescriptorSddl TestFolderSdOwner {  # This sets the owner to Administrators
            Path = $TestFolderOwner
            ObjectType = "Directory"
            Sddl = "O:BA"
            DependsOn = "[File]TestFolderOwner"
        }

        cSecurityDescriptorSddl TestFolderSdSacl { # Some auditing (2 not inherited; 1 inherited; only 2 non inherited should count)
            Path = $TestFolderSacl
            ObjectType = "Directory"
            Sddl = "S:AI(AU;OICISAFA;FA;;;WD)(AU;OICISA;WD;;;SY)(AU;OICIIDSA;FA;;;WD)"
            DependsOn = "[File]TestFolderSacl"
        }

        cSecurityDescriptorSddl TestFolderSdDacl { # Protected DACL from Windows folder (so this should disable inheritance)
            Path = $TestFolderDacl
            ObjectType = "Directory"
            Sddl = "D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)"
            DependsOn = "[File]TestFolderDacl"
        }

        Registry TestKey {
            Ensure = "Present"
            Key = $TestKey
            ValueName= "" 
        }

        cSecurityDescriptorSddl TestKeyFullSd {  # Instead of splitting the SD parts, use an SD with all parts
            Path = $TestKey
            ObjectType = "RegistryKey"
            Sddl = "O:BAG:SYD:PAI(A;OICI;KR;;;RC)(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;CI;KA;;;BU)"
            DependsOn = "[Registry]TestKey"
        }
    }
}