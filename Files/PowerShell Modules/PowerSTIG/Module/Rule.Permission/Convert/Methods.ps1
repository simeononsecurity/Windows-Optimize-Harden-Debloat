# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
    .SYNOPSIS
        Parses the rawString from the rule to retrieve the PermissionTargetPath
#>
function Get-PermissionTargetPath
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $StigString
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    switch ($stigString)
    {
        # Do not use $env: for environment variables. They will not be able to be converted to text for XML.
        # Get path for permissions that pertains to event logs
        { $stigString -match $regularExpression.WinEvtDirectory }
        {
            $parentheseMatch = $stigString | Select-String -Pattern $regularExpression.eventLogName

            if ( $stigString -match $regularExpression.dnsServerLog )
            {
                $childPath = 'DNS Server.evtx'
            }
            else
            {
                $childPath = $parentheseMatch.Matches.Groups[-1].Value.trim()
            }

            $permissionTargetPath = '%windir%\SYSTEM32\WINEVT\LOGS\' + $childPath
            break
        }

        # Get path for permissions that pertains to eventvwr.exe
        { $stigString -match $regularExpression.eventViewer }
        {
            $permissionTargetPath = '%windir%\SYSTEM32\eventvwr.exe'
            break
        }

        # Get path that pertains to C:\

        { $stigString -match $regularExpression.cDrive }
        {
            $permissionTargetPath = '%SystemDrive%\'
            break
        }

        # Get path that pertains to Sysvol
        { $stigString -match $regularExpression.SysVol}
        {
            $permissionTargetPath = '%windir%\sysvol'
            break
        }

        # Get path that pertains to  C:\Windows
        { $stigString -match $regularExpression.systemRoot }
        {
            $permissionTargetPath = '%windir%'
            break
        }

        # Get path that pertains to registry Installed Components key
        { $stigString -match $regularExpression.permissionRegistryInstalled }
        {
            $permissionTargetPath = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components\'
            break
        }

        # Get path that pertains to registry Winlogon key
        { $stigString -match $regularExpression.permissionRegistryWinlogon }
        {
            $permissionTargetPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\'
            break
        }

        # Get path that pertains to registry WinReg key
        { $stigString -match $regularExpression.permissionRegistryWinreg }
        {
            $permissionTargetPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\'
            break
        }

        # Get path that pertains to registry NTDS key
        { $stigString -match $regularExpression.permissionRegistryNTDS }
        {
            $permissionTargetPath = '%windir%\NTDS\*.*'
            break
        }

        # Get path that pertains to both program files directories
        { $stigString -match $regularExpression.programFiles }
        {
            $permissionTargetPath = '%ProgramFiles%;%ProgramFiles(x86)%'
            break
        }

        # Get crypto folder path
        { $stigString -match $regularExpression.cryptoFolder }
        {
            $permissionTargetPath = '%ALLUSERSPROFILE%\Microsoft\Crypto\Keys'
            break
        }

        # Get path that pertains to Admin Shares
        { $stigString -match $regularExpression.adminShares }
        {
            $permissionTargetPath = $null
            break
        }

        # Get Active Directory Path
        { $stigString -match $regularExpression.ADAuditPath }
        {
            $ADPath = (Select-String -InputObject $stigString -Pattern $regularExpression.ADAuditPath) -replace $regularExpression.ADAuditPath, "" -replace " object.*", ""
            $permissionTargetPath = $aDAuditPath.$($ADPath.Trim())
            break
        }

        # Get HKLM\Security path
        {
            $stigString -match $regularExpression.hklmSecurity -and
            $stigString -match $regularExpression.hklmSoftware -and
            $stigString -match $regularExpression.hklmSystem
        }
        {
            $permissionTargetPath = 'HKLM:\SECURITY;HKLM:\SOFTWARE;HKLM:\SYSTEM'
            break
        }

        # Get the individual HKLM paths
        { $stigString -match $regularExpression.hklmSecurity }
        {
            $permissionTargetPath = 'HKLM:\SECURITY'
            break
        }

        { $stigString -match $regularExpression.hklmSoftware }
        {
            $permissionTargetPath = 'HKLM:\SOFTWARE'
            break
        }

        { $stigString -match $regularExpression.hklmSystem }
        {
            $permissionTargetPath = 'HKLM:\SYSTEM'
            break
        }

        # Get path for C:, Program file, and Windows
        {
            $stigString -match $regularExpression.rootOfC -and
            $stigString -match $regularExpression.winDir -and
            $stigString -match $regularExpression.programFilesWin10
        }
        {
            $permissionTargetPath = '%SystemDrive%;%ProgramFiles%;%Windir%'
            break
        }
        {
            $stigString -match $regularExpression.rootOfC -and
            $stigString -notmatch $regularExpression.winDir -and
            $stigString -notmatch $regularExpression.programFileFolder
        }
        {
            $permissionTargetPath = '%SystemDrive%\'
            break
        }
        { $stigString -match $regularExpression.winDir }
        {
            $permissionTargetPath = '%Windir%'
            break
        }
        {  $stigString -match $regularExpression.programFileFolder }
        {
            $permissionTargetPath = '%ProgramFiles%'
            break
        }
        { $stigString -match $regularExpression.programFiles86 }
        {
            $permissionTargetPath = '%ProgramFiles(x86)%'
            break
        }
        { $stigString -match $regularExpression.inetpub }
        {
            $permissionTargetPath = '%SystemDrive%\inetpub'
            break
        }
        # SQL Server install folder
        { $stigString -match $regualrExpression.sqlInstallDirectory }
        {
            # ToDo since this is going to be an OrgSetting need to populate test string here if possible
            $permissionTargetPath = $null
            break
        }

        default
        {
            break
        }
    }

    return $permissionTargetPath
}

<#
    .SYNOPSIS
        This function calls ConvertTo-AccessControlEntry but allows to get AccessControlEntry objects,
        however this allows us to handle edge cases in the rawString from the xccdf.
#>
function Get-PermissionAccessControlEntry
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $StigString
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"
    switch ($stigString)
    {
        { $stigString -match $regularExpression.permissionRegistryWinlogon }
        {
            <#
                Permission rule that pertains to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\
                This rule has an edge case which specifies the same inheritance to all the principals
                and is not in the same format as the other rules.
            #>
            return ConvertTo-AccessControlEntry -StigString $stigString -inheritanceInput 'This key and subkeys'
        }

        { $stigString -match $regularExpression.InheritancePermissionMap }
        {
            return ConvertTo-AccessControlEntryIF -StigString $stigString
        }

        { $stigString -join " " -match $regularExpression.TypePrincipalAccess }
        {
            return ConvertTo-AccessControlEntryGrouped -StigString $stigString
        }

        { $stigString -match $regularExpression.cryptoFolder }
        {
            $cryptoFolderStigString = "SYSTEM, Administrators - Full Control - This folder, subfolders and files"
            return ConvertTo-AccessControlEntry -StigString $cryptoFolderStigString
        }

        { $stigString -match $regularExpression.inetpub }
        {
            # In IIS Server Stig rule V-76745 says creator/owner should have special permissions to subkeys so we ignore it. All rules that are properly documented are converted
            $inetpubFolderStigString = @()
            foreach ($line in $stigString)
            {
                if ($line -notMatch "Creator/Owner" -and $line -match ":")
                {
                    $inetpubFolderStigString += ($line -replace ': ', ' - ') -replace '\(built-in security group\)'
                }
            }

            return ConvertTo-AccessControlEntry -StigString $inetpubFolderStigString
        }

        { $stigString -match $regularExpression.auditingTab }
        {
            return ConvertTo-FileSystemAuditRule -CheckContent $stigString
        }

        default
        {
            return ConvertTo-AccessControlEntry -StigString $stigString
        }
    }
}

<#
    .SYNOPSIS
        This function converts the raw text from the STIG rule to a hashtable with
        the following keys: Principal,FileSystemRights, and Inheritance. This is to
        handle scenarios where a target has multiple principals assigned permissions
        to it.
#>
function ConvertTo-AccessControlEntryGrouped
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $StigString
    )

    $accessControlEntryPrincipal = $stigString | Select-String -Pattern "Principal\s*-"
    $accessControlEntryType      = $stigString | Select-String -Pattern "Type\s*-"
    $accessControlEntryAccess    = $stigString | Select-String -Pattern "Access\s*-"
    $accessControlEntryApplies   = $stigString | Select-String -Pattern "Applies To\s*-"
    $accessControlEntrySpecial   = $stigString | Select-String -Pattern "\(Access - Special\s*"

    foreach ($entry in $accessControlEntryType)
    {
        $type = ($entry.ToString() -Split "-")[1].Trim()

        $principalObject = $accessControlEntryPrincipal |
            Where-Object {$PSItem.LineNumber -gt $entry.LineNumber} |
                Sort-Object -Property LineNumber |Select-Object -First 1

        $principal = ($principalObject.ToString() -split '-')[1].Trim()

        $rightsObject = $accessControlEntryAccess |
            Where-Object {$PSItem.LineNumber -gt $entry.LineNumber} |
                Sort-Object -Property LineNumber | Select-Object -First 1

        $rights = ($RightsObject.ToString() -split "-")[1].Trim()

        $inheritanceObject = $accessControlEntryApplies |
            Where-Object {$PSItem.LineNumber -gt $RightsObject.LineNumber} |
                Sort-Object -Property LineNumber | Select-Object -First 1

        if ($inheritanceObject)
        {
            $inheritance = ($InheritanceObject.ToString() -split "-")[1].Trim()
        }
        else
        {
            $inheritance = ""
        }

        if ($rights -eq "Special")
        {
            $specialPermissions = $accessControlEntrySpecial |
                Where-Object {$PSItem.LineNumber -gt $rightsObject.LineNumber} |
                    Sort-Object -Property LineNumber | Select-Object -First 1

            if ($specialPermissions.ToString().Contains(':'))
            {
                $rights = ($specialPermissions -split ':')[1].Trim()
            }
            else
            {
                $rights = ($specialPermissions -split '=')[1].Trim()
            }

            $rights = $rights.Substring(0,$rights.Length -1)
        }

        $accessControlEntries += [pscustomobject[]]@{
            Principal          = $principal
            ForcePrincipal     = Get-ForcePrincipal -StigString $stigString
            Rights             = Convert-RightsConstant -RightsString $rights
            Inheritance        = $inheritanceConstant[[string]$inheritance.trim()]
            Type               = $type
        }
    }
    return $accessControlEntries
}

<#
    .SYNOPSIS
        Converts permission rules entries that have an inheritance mapping
#>
function ConvertTo-AccessControlEntryIF
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $StigString
    )

    $accessControlEntryMatches = $stigString | Select-String -Pattern $regularExpression.InheritancePermissionMap
    $permissions = $stigString | Select-String -Pattern $regularExpression.PermissionRuleMap

    foreach ($entry in $accessControlEntryMatches)
    {
        $entry = $entry -replace ':', ' - ' -replace '\)\s*\(', ') - ('
        foreach ($permission in $permissions)
        {
            $perm = $permission -split '-'
            $perm[0] = $perm[0] -replace '\(','\(' -replace '\)','\)'
            $entry = $entry -replace $perm[0].Trim(), $perm[1].Trim()
        }

        $principal, [string]$inheritance, $fileSystemRights = $entry -split $regularExpression.spaceDashSpace

        if (-not $inheritanceConstant[[string]$inheritance.trim()])
        {
            $inheritance = ""
        }
        else
        {
            $inheritance = $inheritanceConstant[[string]$inheritance.trim()]
        }

        $accessControlEntries += [pscustomobject[]]@{
            Principal      = $principal.trim()
            ForcePrincipal = Get-ForcePrincipal -StigString $stigString
            Rights         = Convert-RightsConstant -RightsString $fileSystemRights
            Inheritance    = $inheritance
        }
    }

    return $accessControlEntries
}

<#
    .SYNOPSIS
        Converts the raw text from the STIG rule hashtable with
        the following keys: Principal,FileSystemRights, and Inheritance.
#>
function ConvertTo-AccessControlEntry
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $StigString,

        [Parameter()]
        [string]
        $InheritanceInput
    )

    $accessControlEntryMatches = $stigString | Select-String -Pattern $regularExpression.spaceDashSpace

    foreach ( $entry in $accessControlEntryMatches )
    {
        if ( $entry -notmatch 'Type|Inherited|Columns|Principal|Applies' )
        {
            <#
                Access control entries are commonly formatted like so: 'Principal - FileSystemRights - Inheritance
                we will split on a regex pattern the represents space dash space ( - )
            #>
            $principals, $fileSystemRights, [string]$inheritance = $entry -split $regularExpression.spaceDashSpace

            if ( $fileSystemRights -match ([RegularExpression]::TextBetweenParentheses) )
            {
                $inheritance = [regex]::Match( $fileSystemRights, ([RegularExpression]::TextBetweenParentheses) ).groups[1].Value

                $fileSystemRights = ($fileSystemRights -split '\(')[0]
            }

            # There is an edge case V-63593 which states the rights should be 'Special' but it doesn't state what the special rights should be so we ignore it.
            if ( $stigString -match $regularExpression.hklmRootKeys -and $fileSystemRights.Trim() -eq 'Special')
            {
                break
            }
            <#
                There is an edge case in V-26070 where the inheritance is specified in the rule outside of the common format
                V-26070 states the inheritance is to be applied to all the prinicpals.  So if an inheritance is passed in from the Inheritance
                parameter we applied to all the prinicipals.  If not we parse the rawString to extract the inheritance.
            #>
            if ( $inheritanceInput )
            {
                $inheritance = $inheritanceInput
            }

            foreach ( $principal in $principals -split ',' )
            {
                $accessControlEntries += [pscustomobject[]]@{
                    Principal      = $principal.trim()
                    ForcePrincipal = Get-ForcePrincipal -StigString $stigString
                    Rights         = Convert-RightsConstant -RightsString $fileSystemRights
                    Inheritance    = $inheritanceConstant[[string]$inheritance.trim()]
                }
            }
        }
    }

    return $accessControlEntries
}

<#
    .SYNOPSIS
        Converts the checkconent from the STIG rule to a hashtable with
        the following keys: AuditFlags, SystemRights, and Inheritance

#>
function ConvertTo-FileSystemAuditRule
{
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    # We are going to set this to pass and if any values are null change it fail
    $this.ConversionStatus = 'pass'

    $fileRights = Get-FileSystemAccessValue -CheckContent $CheckContent
    $principal = ($CheckContent | Select-String -Pattern '(?<=select\sthe\s").*(?="\srow)|(?<=Principal:).*(?=$)').Matches.Value
    $inheritance = Get-FileSystemInheritance -CheckContent $CheckContent

    $result = [hashtable]@{
        Principal   = $principal.trim()
        Rights      = Convert-RightsConstant -RightsString ($fileRights -join ',')
        Inheritance = $inheritanceConstant[[string]$inheritance.trim()]
    }

    if ($null -eq $result.Principal -or $null -eq $result.Rights -or $null -eq $result.Inheritance)
    {
        $this.ConversionStatus = 'fail'
    }

    return $result
}
<#
    .SYNOPSIS
        Converts strings describing the fileRights permissions to constants that are usable.
        Additonally this addresses the edge case when the fileRights are seperated by a forward slash "/"
#>
function Convert-RightsConstant
{
    [CmdletBinding()]
    [OutputType([array])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $RightsString
    )

    foreach ( $string in $RightsString )
    {
        $values = @()
        $rights = $(
            if ($string.Contains(',') -and $string.Contains('/') -and $this.RawString -match 'Auditing tab')
            {
                $string.Split(',')
            }
            elseif ($string.Contains('/'))
            {
                $string.Split('/')
            }
            else
            {
                $string.Split(',')
            }
        )

        foreach ($right in $rights)
        {
            switch ($this.dscresource)
            {
                'ActiveDirectoryAuditRuleEntry'
                {
                    $values += $activeDirectoryRightsConstant[$right.trim()]
                }
                'RegistryAccessEntry'
                {
                    $values += $registryRightsConstant[$right.trim()]
                }
                'NTFSAccessEntry'
                {
                    $values += $fileRightsConstant[$right.trim()]
                }
                'FileSystemAuditRuleEntry'
                {
                    $values += $auditFileSystemRights[$right.trim()]
                }
                '(blank)'
                {
                    $values += $activeDirectoryRightsConstant[$right.trim()]
                }
            }
        }
    }

    return $values -join ','
}

<#
    .SYNOPSIS
        Checks if the permission rule target has multiple paths

    .PARAMETER PermissionPath
        Permission rule target path
#>
function Test-MultiplePermissionRule
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]
        $PermissionPath
    )

    if ( $PermissionPath -match ';')
    {
        return $true
    }

    return $false
}

<#
    .SYNOPSIS
        Returns an array of permission rule target paths

    .PARAMETER PermissionPath
        Permission rule target path
#>
function Split-MultiplePermissionRule
{
    [CmdletBinding()]
    [OutputType([System.Array])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $result = @()
    [System.Collections.ArrayList]$contentRanges = @()
    # Test for multiple paths at HKLMRoot
    if ($checkContent -match $regularExpression.hklmRootKeys)
    {
        $hklmSecurityMatch  = $checkContent | Select-String -Pattern $regularExpression.hklmSecurity
        $hklmSoftwareMatch  = $checkContent | Select-String -Pattern $regularExpression.hklmSoftware
        $hklmSystemMatch    = $checkContent | Select-String -Pattern $regularExpression.hklmSystem
        $lastPermissonMatch = $checkContent | Select-String -Pattern $regularExpression.spaceDashAnythingSpaceDash | Select-Object -Last 1

        [void]$contentRanges.Add(($hklmSecurityMatch.LineNumber - 1)..($hklmSoftwareMatch.LineNumber - 2))
        [void]$contentRanges.Add(($hklmSoftwareMatch.LineNumber - 1)..($hklmSystemMatch.LineNumber - 2))
        [void]$contentRanges.Add(($hklmSystemMatch.LineNumber - 1)..($lastPermissonMatch.LineNumber - 1))

        $headerLineRange = 0..($hklmSecurityMatch.LineNumber - 2)
        $footerLineRange = ($lastPermissonMatch.LineNumber)..($checkContent.Length - 1)
    }
    elseif (
        $checkContent -match $regularExpression.rootOfC -and
        $checkContent -match $regularExpression.programFilesWin10 -and
        $checkContent -match $regularExpression.winDir
    )
    {
        $rootOfCMatch = $checkContent | Select-String -Pattern $regularExpression.rootOfC | Select-Object -First 1
        $programFilesMatch = $checkContent | Select-String -Pattern $regularExpression.programFileFolder
        $windowsDirectoryMatch = $checkContent | Select-String -Pattern $regularExpression.winDir
        $icaclsMatch = $checkContent | Select-String -Pattern 'Alternately\suse\sicacls'

        [void]$contentRanges.Add(($rootOfCMatch.LineNumber - 1)..($programFilesMatch.LineNumber - 2))
        [void]$contentRanges.Add(($programFilesMatch.LineNumber - 1)..($windowsDirectoryMatch.LineNumber - 2))
        [void]$contentRanges.Add(($windowsDirectoryMatch.LineNumber - 1)..($icaclsMatch.LineNumber - 2))

        $headerLineRange = 0..($rootOfCMatch.LineNumber - 2)
        $footerLineRange = ($icaclsMatch.LineNumber - 1)..($icaclsMatch.LineNumber - 1)
    }
    else
    {
        $programFileTargets = '^\\Program Files and ','and \\Program Files \(x86\)'
        foreach ($target in $programFileTargets)
        {
            $result += Join-CheckContent -Body ($checkContent -replace $target)
        }

        return $result
    }

    foreach ($range in $contentRanges)
    {
        $result += Join-CheckContent -Header $checkContent[$headerLineRange] -Body $checkContent[$range] -Footer $checkContent[$footerLineRange]
    }

    return $result
}

<#
    .SYNOPSIS
        Retrieves the Force Principal attribute
#>
function Get-ForcePrincipal
{
    [CmdletBinding()]
    [OutputType([boolean])]
    param
    (
        [psobject]
        $stigString
    )

    # Setting default value for the time being. In the future additional logic could be added here in order to dynamically determine what this should be.
    return $false
}

<#
    .SYNOPSIS
        Converts a string array into a multi-line string object
#>
function Join-CheckContent
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $Header,

        [Parameter()]
        [string[]]
        [AllowEmptyString()]
        $Body,

        [Parameter()]
        [string[]]
        [AllowEmptyString()]
        $Footer
    )

    $stringBuilder = [System.Text.StringBuilder]::new()

    foreach ($line in $Header)
    {
        [void]$stringBuilder.AppendLine($line)
    }

    foreach ($line in $Body)
    {
        [void]$stringBuilder.AppendLine($line)
    }

    foreach ($line in $Footer)
    {
        [void]$stringBuilder.AppendLine($line)
    }

    return $stringBuilder.ToString()
}

<#
    .SYNOPSIS
        Retrieves the file system inheritance setting from the CheckContent
#>
function Get-FileSystemInheritance
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $results = @()

    foreach ($line in $CheckContent)
    {
        # $inheritanceConstant comes from Rule.Permission\Convert\Data.ps1
        foreach ($key in $inheritanceConstant.keys)
        {
            $result = $line | Select-String -Pattern $key

            if ($result)
            {
                $results += $result
            }
        }
    }

    if ($results.count -gt 1)
    {
        throw "Multiple results have been found."
    }

    return $results.Matches.Value
}

<#
    .SYNOPSIS
        Retrieves the file system access setting from the CheckContent
#>
function Get-FileSystemAccessValue
{
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )
    $results = @()

    foreach ($line in $CheckContent)
    {
        # $auditFileSystemRights comes from Rule.Permission\Convert\Data.ps1
        foreach ($key in $auditFileSystemRights.keys)
        {
            $result = $line | Select-String -Pattern $key

            if ($result)
            {
                $results += $result
            }
        }
    }

    return $results.Matches.Value
}

#endregion
