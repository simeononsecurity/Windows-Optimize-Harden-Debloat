# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
# Header

#region Get-DomainName

<#
    .SYNOPSIS
        Enforces the behavior of getting the domain name.
        If a domain name is provided, it will be used.
        If a domain name is not provided, the domain name of the generating system will be used.
    .PARAMETER DomainName
        The FQDN of the domain the configuration will be running on.
    .PARAMETER ForestName
        The FQDN of the forest the configuration will be running on.
    .PARAMETER Format
        Determines the format in which to convert the FQDN provided into and return back
    .OUTPUTS
        string
    .EXAMPLE
        Get-DomainName -DomainName "contoso.com" -Format FQDN

        Returns "contoso.com"
    .EXAMPLE
        Get-DomainName -DomainName "contoso.com" -Format NetbiosName

        Returns "contoso"
    .EXAMPLE
        Get-DomainName -ForestName "contoso.com" -Format DistinguishedName

        Returns "DC=contoso,DC=com"
#>
Function Get-DomainName
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'DomainName')]
        [AllowNull()]
        [AllowEmptyString()]
        [string]
        $DomainName,

        [Parameter(Mandatory = $true, ParameterSetName = 'ForestName')]
        [AllowNull()]
        [AllowEmptyString()]
        [string]
        $ForestName,

        [Parameter(ParameterSetName = 'DomainName')]
        [Parameter(ParameterSetName = 'ForestName')]
        [ValidateSet('FQDN', 'NetbiosName', 'DistinguishedName')]
        [string]
        $Format = 'FQDN'
    )

    $fqdn = [string]::Empty

    if ($PSCmdlet.ParameterSetName -eq 'DomainName')
    {
        if ( [string]::IsNullOrEmpty( $DomainName ) )
        {
            $fqdn = Get-DomainFQDN
        }
        else
        {
            $fqdn = $DomainName
        }
    }
    else
    {
        if ( [string]::IsNullOrEmpty( $ForestName ) )
        {
            $fqdn = Get-ForestFQDN
        }
        else
        {
            $fqdn = $ForestName
        }
    }

    if ([string]::IsNullOrEmpty($fqdn))
    {
        Write-Warning "$($PSCmdlet.ParameterSetName) was not found."
    }

    switch ($format)
    {
        'FQDN'
        {
            return $fqdn
        }
        'NetbiosName'
        {
            return Get-NetbiosName -FQDN $fqdn
        }
        'DistinguishedName'
        {
            return Get-DistinguishedName -FQDN $fqdn
        }
    }
}

<#
    .SYNOPSIS
        Returns $env:USERDNSDOMAIN to support mocking in unit tests
#>
Function Get-DomainFQDN
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    ( )

    return $env:USERDNSDOMAIN
}

<#
    .SYNOPSIS
        Calls ADSI to discover the forest root (DN) and converts it to an FQDN.
#>
Function Get-ForestFQDN
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    ( )

    $forestRoot = [ADSI]"LDAP://RootDSE"
    return $forestRoot.rootDomainNamingContext -replace '^DC=', '' -replace '.DC=', '.'
}

Function Get-NetbiosName
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $FQDN
    )

    $parts = Get-DomainParts -FQDN $FQDN
    if ($parts.Count -gt 1)
    {
        return $parts[0]
    }
    else
    {
        return $parts
    }
}

Function Get-DistinguishedName
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [string]
        $FQDN
    )

    $parts = Get-DomainParts -FQDN $FQDN
    return Format-DistinguishedName -Parts $parts
}

Function Format-DistinguishedName
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [string[]]
        $Parts
    )

    $distinguishedName = ""
    $lastIndex = $Parts.Count - 1

    foreach ($part in $Parts)
    {
        if ($part -eq $Parts[$lastIndex])
        {
            $distinguishedName += 'DC=' + $part.ToString()
        }
        else
        {
            $distinguishedName += 'DC=' + $part.ToString() + ','
        }
    }

    return $distinguishedName.ToString()
}

Function Get-DomainParts
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $FQDN
    )

    return $FQDN.Split('{.}')
}
#endregion

<#
    .SYNOPSIS
        Returns an array of available STIGs with the associated Technology,
        TechnologyVersion, TechnologyRole, and StigVersion. This function is a
        wrapper for the STIG class. The return of this function call will
        provide you with the values needed to generate the STIG ruleset.
    .PARAMETER Technology
        The STIG technology target
    .PARAMETER ListAvailable
        A switch that returns all of the STIG's in the module.
    .EXAMPLE
        Get-Stig -ListAvailable
    .EXAMPLE
        Get-Stig -Technology WindowsServer
#>
Function Get-Stig
{
    [CmdletBinding()]
    [OutputType([PSObject[]])]
    param
    (
        [Parameter(ParameterSetName = 'All')]
        [switch]
        $ListAvailable
    )

    dynamicparam
    {
        $parameterName = 'Technology'
        $attributes = new-object System.Management.Automation.ParameterAttribute
        $attributes.ParameterSetName = "__Technology"
        $attributes.Mandatory = $false
        $attributeCollection = new-object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $attributeCollection.Add($attributes)
        $values = [Stig]::ListAvailable($null) | Select-Object -Unique Technology -ExpandProperty Technology
        $ValidateSet = new-object System.Management.Automation.ValidateSetAttribute($values)
        $attributeCollection.Add($ValidateSet)

        $Technology = new-object -Type System.Management.Automation.RuntimeDefinedParameter($parameterName, [string], $attributeCollection)
        $paramDictionary = new-object -Type System.Management.Automation.RuntimeDefinedParameterDictionary
        $paramDictionary.Add($parameterName, $Technology)
        return $paramDictionary
    }

    process
    {
        <#
            The ListAvailable switch is only used to prevent the $Technology
            parameter from being entered, so that the List available method is
            passed a null filter.
        #>
        return [STIG]::ListAvailable($Technology.Value)
    }
}
