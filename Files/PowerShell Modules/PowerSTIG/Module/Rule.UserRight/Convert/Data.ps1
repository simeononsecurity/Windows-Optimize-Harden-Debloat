
# This is used to validate strings and return the internal windows constant
data userRightNameToConstant
{
    ConvertFrom-StringData -StringData @'
        Access Credential Manager as a trusted caller = SeTrustedCredManAccessPrivilege
        Access this computer from the network = SeNetworkLogonRight
        Act as part of the operating system = SeTcbPrivilege
        Add workstations to domain = SeMachineAccountPrivilege
        Adjust memory quotas for a process = SeIncreaseQuotaPrivilege
        Allow log on locally = SeInteractiveLogonRight
        Allow log on through Remote Desktop Services = SeRemoteInteractiveLogonRight
        Allow log on through Terminal Services = SeRemoteInteractiveLogonRight
        Back up files and directories = SeBackupPrivilege
        Bypass traverse checking = SeChangeNotifyPrivilege
        Change the system time = SeSystemtimePrivilege
        Change the time zone = SeTimeZonePrivilege
        Create a pagefile = SeCreatePagefilePrivilege
        Create a token object = SeCreateTokenPrivilege
        Create global objects = SeCreateGlobalPrivilege
        Create permanent shared objects = SeCreatePermanentPrivilege
        Create symbolic links = SeCreateSymbolicLinkPrivilege
        Debug programs = SeDebugPrivilege
        Deny access to this computer from the network = SeDenyNetworkLogonRight
        Deny log on as a batch job = SeDenyBatchLogonRight
        Deny log on as a service = SeDenyServiceLogonRight
        Deny log on locally = SeDenyInteractiveLogonRight
        Deny log on through Remote Desktop Services = SeDenyRemoteInteractiveLogonRight
        Deny log on through Terminal Services  = SeDenyRemoteInteractiveLogonRight
        Enable computer and user accounts to be trusted for delegation = SeEnableDelegationPrivilege
        Force shutdown from a remote system = SeRemoteShutdownPrivilege
        Generate security audits = SeAuditPrivilege
        Impersonate a client after authentication = SeImpersonatePrivilege
        Increase a process working set = SeIncreaseWorkingSetPrivilege
        Increase scheduling priority = SeIncreaseBasePriorityPrivilege
        Load and unload device drivers = SeLoadDriverPrivilege
        Lock pages in memory = SeLockMemoryPrivilege
        Log on as a batch job = SeBatchLogonRight
        Log on as a service = SeServiceLogonRight
        Manage auditing and security log = SeSecurityPrivilege
        Modify an object label = SeRelabelPrivilege
        Modify firmware environment values = SeSystemEnvironmentPrivilege
        Perform volume maintenance tasks = SeManageVolumePrivilege
        Profile single process = SeProfileSingleProcessPrivilege
        Profile system performance = SeSystemProfilePrivilege
        Remove computer from docking station = SeUndockPrivilege
        Replace a process level token = SeAssignPrimaryTokenPrivilege
        Restore files and directories = SeRestorePrivilege
        Shut down the system = SeShutdownPrivilege
        Synchronize directory service data = SeSyncAgentPrivilege
        Take ownership of files or other objects = SeTakeOwnershipPrivilege
'@
}
