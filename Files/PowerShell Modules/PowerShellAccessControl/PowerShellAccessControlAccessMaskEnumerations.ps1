# See after Add-Type for generic rights mapping
Add-Type @"
using System;
namespace PowerShellAccessControl {

    // Share enumeration from: http://blogs.msdn.com/b/helloworld/archive/2008/06/10/common-accessmask-value-when-configuring-share-permission-programmatically.aspx
    [Flags]
    public enum LogicalShareRights {
        FullControl      = 0x001f01ff,
        Read             = 0x001200a9, 
        Change           = 0x001301bf
    }

    // Enum info from here: http://msdn.microsoft.com/en-us/library/cc244650.aspx
    // Generic mappings (used in a future release):
    //   - Read: Server object: ReadServer; Printer object: ReadPrinter; job object: ReadJob
    //   - Write: Server object: WriteServer; Printer object: WritePrinter; job object: WriteJob
    //   - Execute: look at previous two, and you get the picture :)
    //   - All: Same as above, but using 'AllAccess'
    [Flags]
    public enum PrinterRights {
        AdministerJob = 0x00010,
        ReadSpoolFile = 0x00020,
        ExecuteJob    = ReadPermissions | AdministerJob,
        ReadJob       = ReadPermissions | ReadSpoolFile,
        WriteJob      = ReadPermissions | AdministerJob,
        JobAllAccess  = Synchronize | RightsRequired | ReadSpoolFile,
        UsePrinter    = 0x00008,
        AdministerPrinter = 0x00004,
        ManagePrinterLimited     = 0x00040,            // PrinterAllAccess
        ExecutePrinter = ReadPermissions | UsePrinter,
        Print          = ExecutePrinter,
        ReadPrinter    = ExecutePrinter,
        WritePrinter   = ExecutePrinter,
        ManagePrinter     = TakeOwnership | ChangePermissions | ReadPermissions | StandardDelete | AdministerPrinter | UsePrinter,
        PrinterAllAccess = ManagePrinter,
        //ManageDocuments   = 0xf0030,
        AdministerServer  = 0x000001,
        EnumerateServer   = 0x000002,
        ServerAllAccess   = TakeOwnership | ChangePermissions | ReadPermissions | StandardDelete | AdministerServer | EnumerateServer,
        ExecuteServer     = ReadPermissions | EnumerateServer,
        ReadServer        = ExecuteServer,
        WriteServer       = ExecuteServer | AdministerServer,
        SpecificFullControl = 0xffff,
        StandardDelete    = 0x010000,  // Standard rights below
        ReadPermissions   = 0x020000,
        ChangePermissions = 0x040000,
        TakeOwnership     = 0x080000,
        RightsRequired    = 0x0d0000,
        Synchronize       = 0x100000
    }

    [Flags]
    public enum WmiNamespaceRights {
        EnableAccount   = 0x000001,
        ExecuteMethods  = 0x000002,
        FullWrite       = 0x000004,
        PartialWrite    = 0x000008,
        ProviderWrite   = 0x000010,
        RemoteEnable    = 0x000020,
        ReadSecurity    = 0x020000,
        EditSecurity    = 0x040000
    }

    // Just Generic rights (see below)
    [Flags]
    public enum WsManAccessRights {
        Full    = 0x10000000,
        Read    = -2147483648, // 0x80000000
        Write   = 0x40000000,
        Execute = 0x20000000 
    }

    [Flags]
    public enum ServiceAccessRights {
        QueryConfig         = 0x0001,
        ChangeConfig        = 0x0002,
        QueryStatus         = 0x0004,
        EnumerateDependents = 0x0008,
        Start               = 0x0010,
        Stop                = 0x0020,
        PauseResume         = 0x0040,
        Interrogate         = 0x0080,
        UserDefinedControl  = 0x0100,
        Delete              = 0x010000,   // StandardDelete
        ReadPermissions     = 0x020000,   // StandardReadPermissions/StandardWrite
        Write               = ReadPermissions | ChangeConfig,
        Read                = ReadPermissions | QueryConfig | QueryStatus | Interrogate | EnumerateDependents,
        ChangePermissions   = 0x040000,   // StandardChangePermissions
        ChangeOwner         = 0x080000,   // StandardChangeOwner
//        Execute             = ReadPermissions | Start | Stop | PauseResume | UserDefinedControl,
        FullControl         = QueryConfig | ChangeConfig | QueryStatus | EnumerateDependents | Start | Stop | PauseResume | Interrogate | UserDefinedControl | Delete | ReadPermissions | ChangePermissions | ChangeOwner
    }

    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa446632%28v=vs.85%29.aspx
    [Flags]
    public enum GenericAceRights {
        GenericAll     = 0x10000000,
        GenericExecute = 0x20000000,
        GenericWrite   = 0x40000000,
        GenericRead    = -2147483648 // 0x80000000
    }

    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379607%28v=vs.85%29.aspx
    [Flags]
    public enum StandardAccessRights {
        StandardDelete            = 0x010000,
        StandardReadPermissions   = 0x020000,
        StandardSynchronize       = 0x100000,
        StandardChangePermissions = 0x040000,
        StandardChangeOwner       = 0x080000,
        StandardAll               = 0x1f0000,
        //StandardExecute           = 0x020000,
        //StandardRead              = 0x020000,
        //StandardWrite             = 0x020000
        StandardRequired          = 0x0d0000,
    }

    [Flags]
    public enum ProcessAccessRights {
        Terminate        = 0x000001,
        CreateThread     = 0x000002,
        SetSessionId     = 0x000004,
        MemoryOperations = 0x000008,
        ReadMemory       = 0x000010,
        WriteMemory      = 0x000020,
        DuplicateHandle  = 0x000040,
        CreateProcess    = 0x000080,
        SetQuota         = 0x000100,
        SetInformation   = 0x000200,
        QueryInformation = 0x000400,
        SuspendResume    = 0x000800,
        QueryLimitedInfo = 0x001000,  // Since this bit is new to Vista+, new AllAccess was created
        AllAccessLegacy  = 0x1f0fff,
        AllAccess        = 0x1fffff,  // Top three bits of object specific rights appear to be unused
        Delete           = 0x010000,
        ReadPermissions  = 0x020000,
        ChangePermissions= 0x040000,
        TakeOwnership    = 0x080000,
        Synchronize      = 0x100000
    }

    [Flags]
    // Not using [System.DirectoryServices.ActiveDirectoryRights] b/c generic rights are mixed in. The way New-AdaptedAcl
    // handles generic rights mapping doesn't work if the enum contains the generic rights enum.
    public enum ActiveDirectoryRights {
        CreateChild       = 0x000001,
        DeleteChild       = 0x000002,
        ListChildren      = 0x000004,
        Self              = 0x000008,
        ReadProperty      = 0x000010,
        WriteProperty     = 0x000020,
        DeleteSubtree     = 0x000040,
        ListContents      = 0x000080,
        ExtendedRight     = 0x000100,
        Delete            = 0x010000,
        ReadPermissions   = 0x020000,
        ChangePermissions = 0x040000,
        TakeOwnership     = 0x080000,
        Synchronize       = 0x100000,
        //Read              = ListChildren | ReadProperty | ListObject | ReadPermissions,
        //Write             = Self | WriteProperty | ReadPermissions,
        //Execute           = ListChildren | ReadPermissions,
        FullControl       = CreateChild | DeleteChild | ListChildren | Self | ReadProperty | WriteProperty | DeleteSubtree | ListContents | ExtendedRight | Delete | ReadPermissions | ChangePermissions | TakeOwnership
    }

    [Flags]
    public enum AppliesTo {
        Object = 1,
        ChildContainers = 2,
        ChildObjects = 4
    }

    namespace NonAccessMaskEnums {
        [Flags]
        public enum SystemMandatoryLabelMask {
            NoWriteUp = 1,
            NoReadUp = 2,
            NoExecuteUp = 4
        }
    }
}
"@

$FileSystemGenericMapping = New-Object PowerShellAccessControl.PInvoke.GenericMapping
$FileSystemGenericMapping.GenericRead    = [System.Security.AccessControl.FileSystemRights] "Read, Synchronize"
$FileSystemGenericMapping.GenericWrite   = [System.Security.AccessControl.FileSystemRights] "Write, ReadPermissions, Synchronize"
$FileSystemGenericMapping.GenericExecute = [System.Security.AccessControl.FileSystemRights] "ExecuteFile, ReadAttributes, ReadPermissions, Synchronize"
$FileSystemGenericMapping.GenericAll     = [System.Security.AccessControl.FileSystemRights] "FullControl"

$RegistryGenericMapping = New-Object PowerShellAccessControl.PInvoke.GenericMapping
$RegistryGenericMapping.GenericRead    = [System.Security.AccessControl.RegistryRights] "ReadKey"
$RegistryGenericMapping.GenericWrite   = [System.Security.AccessControl.RegistryRights] "WriteKey"
$RegistryGenericMapping.GenericExecute = [System.Security.AccessControl.RegistryRights] "CreateLink, ReadKey"
$RegistryGenericMapping.GenericAll     = [System.Security.AccessControl.RegistryRights] "FullControl"

$PrinterGenericMapping = New-Object PowerShellAccessControl.PInvoke.GenericMapping
$PrinterGenericMapping.GenericRead    = [PowerShellAccessControl.PrinterRights] "ExecutePrinter"
$PrinterGenericMapping.GenericWrite   = [PowerShellAccessControl.PrinterRights] "ExecutePrinter"
$PrinterGenericMapping.GenericExecute = [PowerShellAccessControl.PrinterRights] "ExecutePrinter"
$PrinterGenericMapping.GenericAll     = [PowerShellAccessControl.PrinterRights] "PrinterAllAccess"

$AdGenericMapping = New-Object PowerShellAccessControl.PInvoke.GenericMapping
$AdGenericMapping.GenericRead    = [PowerShellAccessControl.ActiveDirectoryRights] "ListChildren, ReadProperty, ListContents, ReadPermissions"
$AdGenericMapping.GenericWrite   = [PowerShellAccessControl.ActiveDirectoryRights] "Self, WriteProperty, ReadPermissions"
$AdGenericMapping.GenericExecute = [PowerShellAccessControl.ActiveDirectoryRights] "ListChildren, ReadPermissions"
$AdGenericMapping.GenericAll     = [PowerShellAccessControl.ActiveDirectoryRights] "CreateChild, DeleteChild, ListChildren, Self, ReadProperty, WriteProperty, DeleteSubtree, ListContents, ExtendedRight, Delete, ReadPermissions, ChangePermissions, TakeOwnership"

$WsManMapping = New-Object PowerShellAccessControl.PInvoke.GenericMapping
$WsManMapping.GenericRead = [PowerShellAccessControl.WsManAccessRights]::Read
$WsManMapping.GenericWrite = [PowerShellAccessControl.WsManAccessRights]::Write
$WsManMapping.GenericExecute = [PowerShellAccessControl.WsManAccessRights]::Execute
$WsManMapping.GenericAll = [PowerShellAccessControl.WsManAccessRights]::Full

$__GenericRightsMapping = @{
    [PowerShellAccessControl.PrinterRights]          = $PrinterGenericMapping
    [System.Security.AccessControl.RegistryRights]   = $RegistryGenericMapping
    [System.Security.AccessControl.FileSystemRights] = $FileSystemGenericMapping
    [PowerShellAccessControl.ActiveDirectoryRights]  = $AdGenericMapping
    [PowerShellAccessControl.WsManAccessRights] = $WsManMapping
}