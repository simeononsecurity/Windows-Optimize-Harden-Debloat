# Needed for ServiceAccessRights enumeration
Import-Module PowerShellAccessControl

Configuration TestAceResource {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    $TestFolder = "C:\powershell\deleteme\dsc_test"
    $TestKey = "HKLM:\SOFTWARE\Dsc_Test"

    Node $ComputerName {

        File TestFolder {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $TestFolder
        }

        # Here's where resource provider to control modifying ACL protection would go

        cAccessControlEntry EveryoneModifyTestFolder {
            Ensure = "Present"
            Path = $TestFolder
            AceType = "AccessAllowed"
            ObjectType = "Directory"
            AccessMask = ([System.Security.AccessControl.FileSystemRights]::Modify)
            Principal = "Everyone"
            DependsOn = "[File]TestFolder"
        }

        cAccessControlEntry EveryoneAuditTestFolder {
            Ensure = "Present"
            Path = $TestFolder
            AceType = "SystemAudit"
            ObjectType = "Directory"
            AccessMask = ([System.Security.AccessControl.FileSystemRights]::FullControl)
            Principal = "Everyone"
            AuditSuccess = $true
            AuditFailure = $true
            DependsOn = "[File]TestFolder"
        }

        Registry TestKey {
            Ensure = "Present"
            Key = $TestKey
            ValueName= "" 
        }

        cAccessControlEntry EveryoneFullControlTestKey {
            Ensure = "Present"
            Path = $TestKey
            ObjectType = "RegistryKey"
            AceType = "AccessAllowed"
            AccessMask = ([System.Security.AccessControl.RegistryRights]::ReadPermissions)
            Principal = "Everyone"
            DependsOn = "[Registry]TestKey"
        }


        cAccessControlEntry UsersRestartBitsService {
            Ensure = "Present"
            Path = "bits"
            ObjectType = "Service"
            AceType = "AccessAllowed"
            AccessMask = ([PowerShellAccessControl.ServiceAccessRights] "Start, Stop")
            Principal = "Everyone"
        }
    }
}