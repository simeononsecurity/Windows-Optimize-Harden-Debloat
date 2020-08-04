# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
data regularExpression
{
    ConvertFrom-StringData -StringData @'
        ADAuditPath = Verify the auditing configuration for (the)?
        adminShares = (?=.*?\\bADMIN\\b\\$)(?=.*?\\bC\\b\\$)(?=.*?\\bIPC\\b\\$).*$
        cDrive = system drive's root directory
        cryptoFolder = ^%ALLUSERSPROFILE%\\\\Microsoft\\\\Crypto$
        dnsServerLog = DNS\\sServer\\.evtx
        eventLogName = \\w+\\.evtx
        eventViewer = eventvwr\.exe
        hklmSecurity = HKEY_LOCAL_MACHINE\\\\SECURITY
        hklmSoftware = HKEY_LOCAL_MACHINE\\\\SOFTWARE
        hklmSystem = HKEY_LOCAL_MACHINE\\\\SYSTEM
        hklmRootKeys = HKEY_LOCAL_MACHINE\\\\(SECURITY|SOFTWARE|SYSTEM)
        InheritancePermissionMap = :\\(\\w\\)\\(\\w\\)
        inetpub = inetpub
        permissionRegistryInstalled = (?=.*?\\bHKEY_LOCAL_MACHINE\\b)(?=.*?\\bInstalled\\sComponents\\b).*$
        permissionRegistryWinlogon = (?=.*?\\bHKEY_LOCAL_MACHINE\\b)(?=.*?\\bWinlogon\\b).*$
        permissionRegistryWinreg = (?=.*?\\bHKEY_LOCAL_MACHINE\\b)(?=.*?\\bwinreg\\b).*$
        permissionRegistryNTDS = (?=.*?\\bHKEY_LOCAL_MACHINE\\b)(?=.*?\\bNTDS\\b).*$
        PermissionRuleMap = \\(\\w\\)\\s*-\\s*\\w
        programFiles = ^\\\\Program\\sFiles\\sand\\s\\\\Program\\sFiles\\s\\(x86\\)
        programFiles86 = ^\\\\Program\\sFiles\\s\\(x86\\)*
        programFileFolder = ^\\\\Program\\sFiles$
        spaceDashAnythingSpaceDash = \\s-[\\s\\S]*?\\s-
        rootOfC = ^C\\:\\\\$
        spaceDashSpace = \\s-\\s
        systemRoot = Windows installation directory
        SysVol = Windows\\\\SYSVOL
        textBetweenParentheses = \\(([^\)]+)\\)
        TypePrincipalAccess = (?:\\bType\\b\\s*-\\s*\\w*\\s*)(?:\\bPrincipal\\b\\s*-\\s*(\\w*\\s*){1,2})(?:\\bAccess\\b\\s*-\\s*\\w*\\s*)
        winDir = ^\\\\Windows
        WinEvtDirectory = %SystemRoot%\\\\SYSTEM32\\\\WINEVT\\\\LOGS
        sqlInstallDirectory = \\<drive\\>:\\\\Program Files\\\\Microsoft Sql Server\\\\
        auditingTab = on the Auditing Tab
'@
}

data aDAuditPath
{
    ConvertFrom-StringData -StringData @'
        domain = {Domain}
        Domain Controller OU = OU=Domain Controllers,{Domain}
        AdminSDHolder = CN=AdminSDHolder,CN=System,{Domain}
        RID Manager$ = CN=RID Manager$,CN=System,{Domain}
        Infrastructure = CN=Infrastructure,{Domain}
'@
}

data fileRightsConstant
{
    ConvertFrom-StringData -StringData @'
        Full Control                     = FullControl
        full access                      = FullControl
        Read                             = Read
        Modify                           = Modify
        Read & execute                   = ReadAndExecute
        Read and execute                 = ReadAndExecute
        Create folders                   = CreateDirectories
        append data                      = AppendData
        Create files                     = CreateFiles
        write data                       = WriteData
        list folder contents             = ListDirectory
        all selected except Full control = AppendData,ChangePermissions,CreateDirectories,CreateFiles,Delete,DeleteSubdirectoriesAndFiles,ExecuteFile,ListDirectory,Modify,Read,ReadAndExecute,ReadAttributes,ReadData,ReadExtendedAttributes,ReadPermissions,Synchronize,TakeOwnership,Traverse,Write,WriteAttributes,WriteData,WriteExtendedAttributes
'@
}

data registryRightsConstant
{
    ConvertFrom-StringData -StringData @'
        Full Control   = FullControl
        Read           = ReadKey
'@
}

data activeDirectoryRightsConstant
{
    ConvertFrom-StringData -StringData @'
        Full Control                  = FullControl
        full access                   = FullControl
        Write all properties          = WriteallProperties
        All extended rights           = AllExtendedRights
        Change infrastructure master  = ChangeInfrastructureMaster
        Modify Permissions            = ModifyPermissions
        Modify Owner                  = ModifyOwner
        Change RID master             = ChangeRIDMaster
        all create                    = Createallchildobjects
        delete and modify permissions = Delete,ModifyPermissions
        (blank)                       = blank
'@
}

data inheritanceConstant
{
    ConvertFrom-StringData -StringData @'
        This key and subkeys               = This Key and Subkeys
        This key only                      = This Key Only
        Subkeys only                       = Subkeys Only
        This folder and subfolders         = This folder and subfolders
        This folder only                   = This folder only
        Subfolders and files only          = Subfolders and files only
        This folder, subfolders, and files = This folder subfolders and files
        This folder, subfolders and files  = This folder subfolders and files
        This folder, subfolder and files   = This folder subfolders and files
        This folder, subfolder, and files  = This folder subfolders and files
        Subfolders only                    = Subfolders only
'@
}

data auditFileSystemRights
{
    ConvertFrom-StringData -StringData @'
        Traverse folder/execute file = Traverse,ExecuteFile
        List folder/read data        = ListDirectory,ReadData
        Read attributes              = ReadAttributes
        Read extended attributes     = ReadExtendedAttributes
        Create files/write data      = CreateFiles,WriteData
        Create folders/append data   = CreateDirectories,AppendData
        Write attributes             = WriteAttributes
        Write extended attributes    = WriteExtendedAttributes
        Delete                       = Delete
        Read permissions             = ReadPermissions
        Modify                       = Modify
'@
}
