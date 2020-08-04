# Needed for ServiceAccessRights enumeration
Import-Module PowerShellAccessControl

Configuration TestSecurityDescriptorResource {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    $TestFolderOwner = "C:\powershell\deleteme\dsc_test_sd_owner"
    $TestFolderSacl = "C:\powershell\deleteme\dsc_test_sd_sacl"
    $TestFolderDacl = "C:\powershell\deleteme\dsc_test_sd_dacl"
    $TestKey = "HKLM:\SOFTWARE\Dsc_Test_sd"

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

        cSecurityDescriptor TestFolderSdOwner {  # This sets the owner to Administrators
            Path = $TestFolderOwner
            ObjectType = "Directory"
            Owner = "Administrators"
            DependsOn = "[File]TestFolderOwner"
        }

        cSecurityDescriptor TestFolderSdSacl { 
            Path = $TestFolderSacl
            ObjectType = "Directory"
            AuditInheritance = "Enabled"
            Audit = @"
                AceType,Principal,FolderRights,AuditSuccess,AuditFailure
                SystemAudit,Everyone,FullControl,false,true
                SystemAudit,Users,Delete,true,true
"@
            DependsOn = "[File]TestFolderSacl"
        }

        cSecurityDescriptor TestFolderSdDacl {
            Path = $TestFolderDacl
            ObjectType = "Directory"
            AccessInheritance = "Disabled"
            Access = @"
                AceType,Principal,FolderRights,AppliesTo,OnlyApplyToThisContainer
                AccessAllowed,Administrators,FullControl
                AccessAllowed,Users,Modify
                AccessDenied,Users,Delete,Object
                AccessDenied,Everyone,CreateDirectories,ChildContainers,true
"@
            DependsOn = "[File]TestFolderDacl"
        }

        Registry TestKey {
            Ensure = "Present"
            Key = $TestKey
            ValueName= "" 
        }

        cSecurityDescriptor TestKeyFullSd { 
            Path = $TestKey
            ObjectType = "RegistryKey"
            Owner = "Administrators"
            Group = "Administrators"
            Access = @"
                Principal,RegistryRights
                Administrators,FullControl
                Users,ReadKey
"@
            Audit = @"
                AceType,Principal,RegistryRights,AuditFailure
                SystemAudit,Everyone,FullControl,true
"@
            DependsOn = "[Registry]TestKey"
        }

    }
}