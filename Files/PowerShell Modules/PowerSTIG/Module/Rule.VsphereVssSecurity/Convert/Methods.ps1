# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions

<#
    .SYNOPSIS
        This function parses the fix text to find the boolean value of ForgedTransmits, then sets the value.

    .PARAMETER RawString
        An array of the raw string data taken from the STIG setting.
#>
function Get-VsphereForgedTransmits
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $FixText
    )

    if ($FixText -match 'Get-VirtualSwitch')
    {
        $vsphereForgedTransmits = ($FixText | Select-String -Pattern '(?<=ForgedTransmits\s)(.\w+)').Matches.Value
    }

    if ($null -ne $vsphereForgedTransmits)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found ForgedTransmits value: {0}" -f $vsphereForgedTransmits)
        return $vsphereForgedTransmits
    }
    else
    {
        return $null
    }
}
<#
    .SYNOPSIS
        This function parses the fix text to find the boolean value of MacChanges, then sets the value.

    .PARAMETER RawString
        An array of the raw string data taken from the STIG setting.
#>
function Get-VsphereMacChange
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $FixText
    )

    if ($FixText -match 'Get-VirtualSwitch')
    {
        $vsphereMacChange = ($FixText | Select-String -Pattern '(?<=MacChanges\s)(.\w+)').Matches.Value
    }

    if ($null -ne $vsphereMacChange)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found MacChanges value: {0}" -f $vsphereMacChange)
        return $vsphereMacChange
    }
    else
    {
        return $null
    }
}
<#
    .SYNOPSIS
        This function parses the fix text to find the boolean value of AllowPromiscuous, then sets the value.

    .PARAMETER RawString
        An array of the raw string data taken from the STIG setting.
#>
function Get-VsphereAllowPromiscuous
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $FixText
    )

    if ($FixText -match 'Get-VirtualSwitch')
    {
        $vsphereAllowPromiscuous = ($FixText | Select-String -Pattern '(?<=AllowPromiscuous\s)(.\w+)').Matches.Value
    }

    if ($null -ne $vsphereAllowPromiscuous)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found AllowPromiscuous value: {0}" -f $vsphereAllowPromiscuous)
        return $vsphereAllowPromiscuous
    }
    else
    {
        return $null
    }
}
