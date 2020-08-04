# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
    .SYNOPSIS
        Retreives the WindowsFeature name from the check-content element in the xccdf

    .PARAMETER CheckContent
        Specifies the check-content element in the xccdf
#>
function Get-WindowsFeatureName
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"
    $windowsFeatureName = @()
    try
    {
        switch ($checkContent)
        {
            { $PSItem -match $regularExpression.WindowsFeatureName }
            {
                <#
                    The regex returns and named capture group called 'featureName'
                    that contains the feature name. $regularExpression.WindowsFeatureName
                    has been updated to incorporate the patterns from
                    $regularExpression.FeatureNameEquals and
                    $regularExpression.FeatureNameSpaceColon. They are both
                    commented out below for now case other STIGs stop parsing correctly.
                    They will be removed as part of Issue #223
                #>
                $null = $PSItem -match $regularExpression.WindowsFeatureName
                $windowsFeatureName += $Matches['featureName']
            }
            # { $PSItem -match $regularExpression.FeatureNameEquals }
            # {                                                     # rem from data files as well
            #     $matches = $checkContent | Select-String -Pattern $regularExpression.FeatureNameEquals
            #     $windowsFeatureName += ( $matches.Matches.Value -replace 'FeatureName\s-eq' ).Trim()
            # }
            { $PSItem -match $regularExpression.FeatureNameSpaceColon }
            {                                                     # rem from data files as well
                $matches = $checkContent | Select-String -Pattern $regularExpression.FeatureNameSpaceColon -AllMatches
                $windowsFeatureName += ( $matches.Matches.Value -replace 'FeatureName\s\:' ).Trim()
            }
            { $PSItem -match $regularExpression.IfTheApplicationExists -and $PSItem -notmatch 'telnet' }
            {
                $matches = $checkContent | Select-String -Pattern $regularExpression.IfTheApplicationExists
                $windowsFeatureName += (($matches.Matches.Value | Select-String -Pattern ([RegularExpression]::TextBetweenQuotes)).Matches.Value -replace '"').Trim()
            }
            { $PSItem -match 'Telnet Client' }
            {
                $windowsFeatureName += 'TelnetClient'
            }
            { $PSItem -match $regularExpression.WebDavPublishingFeature }
            {
                $windowsFeatureName += 'Web-DAV-Publishing'
            }
            { $PSItem -match $regularExpression.SimpleTCP }
            {
                $windowsFeatureName += 'SimpleTCP'
            }
            { $PSItem -match $regularExpression.IISHostableWebCore }
            {
                $windowsFeatureName += 'IIS-HostableWebCore'
            }
            { $PSItem -match $regularExpression.IISWebserver }
            {
                $windowsFeatureName += 'IIS-WebServer'
            }
        }
    }
    catch
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] WindowsOptionalFeature : Not Found"
        return $null
    }
    return ($windowsFeatureName -join ',')
}

<#
    .SYNOPSIS
        Retreives the WindowsFeature InstallState from the check-content element in the xccdf

    .PARAMETER CheckContent
        Specifies the check-content element in the xccdf
#>
function Get-FeatureInstallState
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $CheckContent
    )

    switch ($checkContent)
    {
        <#
            Currently ALL WindowsFeatureRules referenced in any of the STIGs will be uninstalled (Absent)
            so the default is Absent. When a STIG rule states a WindowsFeature is to be installed (Present)
            we can add the logic here.
        #>
        {$PSItem -eq $false}
        {
            return [ensure]::Present
        }
        default
        {
            [ensure]::Absent
        }
    }
}

<#
    .SYNOPSIS
        Test if the check-content contains WindowsFeatures to install/uninstall.

    .PARAMETER CheckContent
        Specifies the check-content element in the xccdf
#>
function Test-MultipleWindowsFeatureRule
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $FeatureName
    )

    if ( $FeatureName -match ',')
    {
        return $true
    }
    return $false
}

<#
    .SYNOPSIS
        Consumes a list of mitigation targets seperated by a comma and outputs an array

    .PARAMETER FeatureName
        A list of comma seperate WindowsFeature names
#>
function Split-WindowsFeatureRule
{
    [CmdletBinding()]
    [OutputType([array])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $FeatureName
    )

    return ( $FeatureName -split ',' )
}
#endregion
