# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
    .SYNOPSIS
        Retreives the mitigation target name from the check-content element in the xccdf

    .PARAMETER CheckContent
        Specifies the check-content element in the xccdf
#>
function Get-MitigationTargetName
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    try
    {
        switch ($checkContent)
        {
            { $PSItem -match '-System' }
            {
                return 'System'
            }
            { $PSItem -match '-Name' }
            {
                # Grab all the text that starts on a new line or with whitespace and ends in .exe
                $executableMatches = $checkContent | Select-String -Pattern '(^|\s)\S*?\.exe' -AllMatches
                return ( $executableMatches.Matches.Value.Trim() ) -join ','

            }
        }
    }
    catch
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Mitigation Target Name : Not Found"
        return $null
    }
}

<#
    .SYNOPSIS
        Retreives the mitigation policy name from the check-content element in the xccdf

    .PARAMETER CheckContent
        Specifies the check-content element in the xccdf
#>
function Get-MitigationPolicyToEnable
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    try
    {
        # Determine if the stig rule contains policies to be enabled
        if ( ( Test-PoliciesToEnable -CheckContent $checkContent ) -eq $false )
        {
            return $null
        }

        $result = @()
        foreach ($line in $checkContent)
        {
            switch ($line)
            {
                { $PSItem -match $regularExpression.IfTheStatusOf }
                {
                    <# 
                    Grab the line that has "If the status of" then grab the text inbetween " and :
                    Check to see if the line was the word 'Enable' in it
                    #>
                    if ($PSItem -match 'Enable')
                    {
                        $result += ( ( $line | Select-String -Pattern $regularExpression.TextBetweenDoubleQuoteAndColon ).Matches.Value -replace '"' -replace ':' ).Trim()
                    }
                    else
                    {
                        $result += ( ( $line | Select-String -Pattern $regularExpression.TextBetweenColonAndDoubleQuote ).Matches.Value -replace '"' -replace ':' ).Trim()
                    }
                }
                { $PSItem -match $regularExpression.ColonSpaceOn }
                {
                    <#
                        This address the edge case where the mitigation is specified to be enabled on a seperate line example (DEP):
                        DEP:
                        Enable: ON

                        ASLR:
                        BottomUp: ON
                        ForceRelocateImages: ON
                    #>
                    if ( $line -match $regularExpression.EnableColon )
                    {
                        $enableLineMatch = ( $checkContent | Select-String -Pattern $line ).LineNumber
                        $result += ( ( $checkContent[$enableLineMatch - 2] ) -replace ':' ).Trim()
                    }
                    else
                    {
                        $result += ( $line -replace $regularExpression.ColonSpaceOn ).Trim()
                    }
                }
            }
        }
        return $result -join ','
    }
    catch
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Mitigation Policy : Not Found"
        return $null
    }
}

<#
    .SYNOPSIS
        Test if the check-content contains mitigations polices to enable.

    .PARAMETER CheckContent
        Specifies the check-content element in the xccdf

    .NOTES
        Currently all rules in the STIG state the policies referenced need to be enabled.
        However that could change in the future or in other STIGs so we need to check for both conditions (Enabled|Disabled)
#>
function Test-PoliciesToEnable
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    foreach ( $line in $checkContent )
    {
        if ( $line -match $regularExpression.IfTheStatusOfIsOff )
        {
            return $true
        }

        if ( $line -match $regularExpression.NotHaveAStatusOfOn )
        {
            return $true
        }
    }
    return $false
}

<#
    .SYNOPSIS
        Consumes a list of mitigation targets seperated by a comma and outputs an array
#>
function Split-ProcessMitigationRule
{
    [CmdletBinding()]
    [OutputType([array])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $MitigationTarget
    )

    return ( $MitigationTarget -split ',' )
}

<#
    .SYNOPSIS
        Check if the string (MitigationTarget) contains a comma. If so the rule needs to be split
#>
function Test-MultipleProcessMitigationRule
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $MitigationTarget
    )

    if ( $MitigationTarget -match ',')
    {
        return $true
    }
    return $false
}
#endregion
