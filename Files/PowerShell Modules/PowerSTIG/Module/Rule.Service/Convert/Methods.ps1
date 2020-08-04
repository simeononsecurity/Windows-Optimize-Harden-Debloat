# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
    .SYNOPSIS
        Parses Check-Content element to retrieve the Service Name.
#>
function Get-ServiceName
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter( Mandatory = $true )]
        [string[]]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    if ( $checkContent -match $regularExpression.McAfee)
    {
        $serviceName = 'masvc'
    }
    elseif ($checkContent -match $regularExpression.SmartCardRemovalPolicy)
    {
        $serviceName = 'SCPolicySvc'
    }
    elseif ($checkContent -match $regularExpression.SecondaryLogon)
    {
        $serviceName = 'seclogon'
    }
    elseif ($checkContent -match $regularExpression.followingservices)
    {
        $regexMatch = $checkContent | Select-String '-'
        $svcArray = @()
        foreach ($match in $regexMatch)
        {
            $svc = $match -replace '-', ''
            if ( $svc.Contains('(') )
            {
                $svc = $svc.ToString().Substring(0, $svc.IndexOf('(') - 1)
            }
            if ( $servicesDisplayNameToName.Contains( $svc.Trim() ) )
            {
                $svc = $servicesDisplayNameToName.$( $svc.Trim() )
            }
            $svcArray += $svc.Trim()
        }
        $serviceName = $svcArray -join ','
    }
    else
    {
        $regexMatch = $checkContent | Select-String ([RegularExpression]::TextBetweenParentheses)

        if ( -not [string]::IsNullOrEmpty( $regexMatch ) )
        {
            $serviceName = $regexMatch.matches.groups[-1].Value
        }
    }
    <#
       There is an edge case with the rule concerning the FTP Service. All service rules have the service names inside of parentheses
       (ex. (servicename)), however the rule pertaining to the FTP service presents this scenario: (Service name: FTPSVC)
    #>
    if ( $serviceName -match 'Service name: FTPSVC' )
    {
        $serviceName = ( $serviceName -split ':' )[-1]
    }

    if ( -not [string]::IsNullOrEmpty( $serviceName ) )
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]  Found service name   : $serviceName"

        $serviceName = $serviceName.Trim()

        Write-Verbose "[$($MyInvocation.MyCommand.Name)]  Trimmed service name : $serviceName"
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]  Found service name   : $false"
        return
    }

    if ( $servicesDisplayNameToName.Contains( $serviceName ) )
    {
        $serviceName = $servicesDisplayNameToName.$serviceName
    }

    return $serviceName
}

<#
    .SYNOPSIS
        Parses Check-Content element to retrieve the Service State.
#>
function Get-ServiceState
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter( Mandatory = $true )]
        [psobject]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    $serviceName = Get-ServiceName -CheckContent $checkContent

    # ServiceState McAfee and Smartcard is running everything else is stopped
    if ($serviceName -match 'masvc' -or $serviceName -eq 'SCPolicySvc')
    {
        return 'Running'
    }
    elseif ($checkContent -match 'is installed and not disabled, this is a finding')
    {
        return 'Stopped'
    }
    elseif ($checkContent -match 'is not set to Automatic, this is a finding' -or
             $checkContent -match 'is not Automatic, this is a finding')
    {
        return 'Running'
    }
    else
    {
        return 'Stopped'
    }
}

<#
    .SYNOPSIS
        Parses Check-Content element to retrieve the Service Startup Type.
#>
function Get-ServiceStartupType
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter( Mandatory = $true )]
        [psobject]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    $serviceName = Get-ServiceName -CheckContent $checkContent

    # StartupType McAfee and Smartcard is Automatic everything else is disabled
    if ($serviceName -match 'masvc' -or $serviceName -eq 'SCPolicySvc')
    {
        return 'Automatic'
    }
    elseif ($checkContent -match 'is installed and not disabled, this is a finding')
    {
        return 'Disabled'
    }
    elseif ($checkContent -match 'is not set to Automatic, this is a finding' -or
        $checkContent -match 'is not Automatic, this is a finding')
    {
        return 'Automatic'
    }
    else
    {
        return 'Disabled'
    }
}
<#
    .SYNOPSIS
        Check if the string (ServiceName) contains a comma. This was added to enable testing of
        the methods used to determine how the test is accomplished.
#>
function Test-MultipleServiceRule
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $ServiceName
    )

    if ( $ServiceName -match ',')
    {
        return $true
    }
    return $false
}
<#
    .SYNOPSIS
        Check if the string (ServiceName) contains Multiple Service names then Splits them. This was added to enable testing of
        the methods used to determine how the test is accomplished.
#>
function Split-MultipleServiceRule
{
    [CmdletBinding()]
    [OutputType([array])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $ServiceName
    )

    return ( $ServiceName -split ',' )
}
#endregion
