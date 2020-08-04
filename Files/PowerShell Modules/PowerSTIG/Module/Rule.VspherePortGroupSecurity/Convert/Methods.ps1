# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions

<#
    .SYNOPSIS
        This function parses the fix text to find the boolean value of ForgedTransmitsInherited, then sets the value.

    .PARAMETER RawString
        An array of the raw string data taken from the STIG setting.
#>
function Get-VsphereForgedTransmitsInherited
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $FixText
    )

    if ($FixText -match 'Get-VirtualPortGroup')
    {
        $vsphereForgedTransmitsInherited = ($FixText | Select-String -Pattern '(?<=ForgedTransmitsInherited\s)(.\w+)').Matches.Value
    }

    if ($null -ne $vsphereForgedTransmitsInherited)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found ForgedTransmitsInherited value: {0}" -f $vsphereForgedTransmitsInherited)
        return $vsphereForgedTransmitsInherited
    }
    else
    {
        return $null
    }
}

<#
    .SYNOPSIS
        This function parses the fix text to find the boolean value of MacChangesInherited, then sets the value.

    .PARAMETER RawString
        An array of the raw string data taken from the STIG setting.
#>
function Get-VsphereMacChangeInherited
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $FixText
    )

    if ($FixText -match 'Get-VirtualPortGroup')
    {
        $vsphereMacChangeInherited = ($FixText | Select-String -Pattern '(?<=MacChangesInherited\s)(.\w+)').Matches.Value
    }

    if ($null -ne $vsphereMacChangeInherited)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found MacChangesInherited value: {0}" -f $vsphereMacChangeInherited)
        return $vsphereMacChangeInherited
    }
    else
    {
        return $null
    }
}

<#
    .SYNOPSIS
        This function parses the fix text to find the boolean value of AllowPromiscuousInherited, then sets the value.

    .PARAMETER RawString
        An array of the raw string data taken from the STIG setting.
#>
function Get-VsphereAllowPromiscuousInherited
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $FixText
    )

    if ($FixText -match 'Get-VirtualPortGroup')
    {
        $vsphereAllowPromiscuousInherited = ($FixText | Select-String -Pattern '(?<=AllowPromiscuousInherited\s)(.\w+)').Matches.Value
    }

    if ($null -ne $vsphereAllowPromiscuousInherited)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found AllowPromiscuousInherited value: {0}" -f $vsphereAllowPromiscuousInherited)
        return $vsphereAllowPromiscuousInherited
    }
    else
    {
        return $null
    }
}
