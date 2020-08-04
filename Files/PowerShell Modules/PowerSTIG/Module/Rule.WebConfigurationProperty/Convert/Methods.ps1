# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
    .SYNOPSIS
        Returns the ConfigSection property for the STIG rule.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-ConfigSection
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    $cleanCheckContent = $checkContent -replace [RegularExpression]::ExcludeExtendedAscii, '"'

    switch ($cleanCheckContent)
    {
        { $PSItem -match $regularExpression.configSection }
        {
            $matchConfigSection = $PSItem | Select-String -Pattern ($regularExpression.configSection) -AllMatches
            $configSection = $matchConfigSection.Matches.Groups.Value -replace " ", "/"

            if ( -not $configSection.StartsWith("/") )
            {
                $configSection = "/" + $configSection
            }
        }
        { $cleanCheckContent -match 'Directory Browsing' }
        {
            $configSection = '/system.webServer/directoryBrowse'
        }
        { $cleanCheckContent -match '\.NET Trust Level' }
        {
            $configSection = '/system.web/trust'
        }
        { $cleanCheckContent -match '\.NET Compilation' }
        {
            $configSection = '/system.web/compilation'
        }
        { $cleanCheckContent -match 'maxUrl|maxAllowedContentLength|Maximum Query String' }
        {
            $configSection = '/system.webServer/security/requestFiltering/requestlimits'
        }
        { $cleanCheckContent -match 'Allow high-bit characters|Allow double escaping' }
        {
            $configSection = '/system.webServer/security/requestFiltering'
        }
        { $cleanCheckContent -match 'Allow unlisted file' }
        {
            $configSection = '/system.webServer/security/requestFiltering/fileExtensions'
        }
        { $cleanCheckContent -match 'Error Pages' }
        {
            $configSection = '/system.webServer/httpErrors'
        }
        { $cleanCheckContent -match 'keepSessionIdSecure' }
        {
            $configSection = '/system.webServer/asp/session'
        }
        { $cleanCheckContent -match 'Machine Key' }
        {
            $configSection = '/system.web/machineKey'
        }
        { $cleanCheckContent -match 'Allow unspecified CGI modules' }
        {
            $configSection = '/system.webServer/security/isapiCgiRestriction'
        }
        { $cleanCheckContent -match 'Allow unspecified ISAPI modules' }
        {
            $configSection = '/system.webServer/security/isapiCgiRestriction'
        }
        { $cleanCheckContent -match 'Regenerate expired session ID|Time-out|Use Cookies' }
        {
            $configSection = '/system.web/sessionState'
        }
    }

    if ($null -ne $configSection)
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Found ConfigSection: $($configSection)"
        return $configSection
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] ConfigSection not found"
        return $null
    }
}

<#
    .SYNOPSIS
        Returns the key and value properties for the STIG rule.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-KeyValuePair
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    switch ( $checkContent )
    {
        { $PSItem -match $regularExpression.keyValuePairLine }
        {
            [string] $matchKeyValuePairLine = $PsItem | Select-String -Pattern $regularExpression.keyValuePairLine -AllMatches

            $keyValuePair = $matchKeyValuePairLine | Select-String -Pattern ([RegularExpression]::KeyValuePair) -AllMatches

            $key = ($keyValuePair.Matches.Groups.value[0]).replace(' ', '')
            $value = $keyValuePair.Matches.Groups.value[-1]
        }
        { $checkContent -match 'Directory Browsing' }
        {
            $key = 'enabled'
            $value = 'false'
        }
        { $checkContent -match '\.NET Compilation' }
        {
            $key = 'debug'
            $value = 'false'
        }
        { $checkContent -match 'Allow high-bit characters' }
        {
            $key = 'allowHighBitCharacters'
            $value = 'false'
        }
        { $checkContent -match 'Allow double escaping' }
        {
            $key = 'allowDoubleEscaping'
            $value = 'false'
        }
        { $checkContent -match 'Allow unlisted file' }
        {
            $key = 'allowUnlisted'
            $value = 'false'
        }
        { $checkContent -match 'maxUrl' }
        {
            $key = 'maxUrl'
            $value = $null
        }
        { $checkContent -match 'maxAllowedContentLength' }
        {
            $key = 'maxAllowedContentLength'
            $value = $null
        }
        { $checkContent -match 'Maximum Query String' }
        {
            $key = 'maxQueryString'
            $value = $null
        }
        { $checkContent -match 'Error Pages' }
        {
            $key = 'errormode'
            $value = 'DetailedLocalOnly'
        }
        { $checkContent -match '\.NET Trust Level' }
        {
            $key = 'level'
            $value = $null
        }
        { $checkContent -match 'Verify the "timeout" is set' }
        {
            $key = 'timeout'
            $value = $null
        }
        { $checkContent -match $regularExpression.HMACSHA256 }
        {
            $key = 'validation'
            $value = 'HMACSHA256'
        }
        { $checkContent -match $regularExpression.autoEncryptionMethod }
        {
            $key = 'decryption'
            $value = 'Auto'
        }
        { $checkContent -match $regularExpression.CGIModules }
        {
            $key = 'notListedCgisAllowed'
            $value = 'false'
        }
        { $checkContent -match $regularExpression.ISAPIModules }
        {
            $key = 'notListedIsapisAllowed'
            $value = 'false'
        }
        { $checkContent -match $regularExpression.useCookies }
        {
            $key = 'cookieless'
            $value = 'UseCookies'
        }
        { $checkContent -match $regularExpression.expiredSession }
        {
            $key = 'regenerateExpiredSessionId'
            $value = 'True'
        }
        { $checkContent -match $regularExpression.sessionTimeout }
        {
            $key = 'timeout'
            $value = $null
        }
    }

    if ($null -ne $key)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found Key: {0}, value: {1}" -f $key, $value)

        return @{
            key   = $key
            value = $value
        }
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] No Key or Value found"
        return $null
    }
}

<#
    .SYNOPSIS
        Tests to see if the stig rule needs to be split into multiples.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Test-MultipleWebConfigurationPropertyRule
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    $matchConfigSection = $checkContent | Select-String -Pattern $regularExpression.configSection -AllMatches
    $matchEncryptionRule = $checkContent | Select-String -Pattern $regularExpression.HMACSHA256 -AllMatches
    $matchMultipleKeyvaluePair = $checkContent | Select-String -Pattern ([RegularExpression]::KeyValuePair) -AllMatches
    $matchUseCookies = $checkContent | Select-String -Pattern $regularExpression.useCookies -AllMatches
    $matchSessionTimeout = $checkContent | Select-String -Pattern $regularExpression.sessionTimeout -AllMatches

    if ($matchConfigSection.Count -gt 1)
    {
        Write-Verbose -message "[$($MyInvocation.MyCommand.Name)] : $true"
        return $true
    }
    elseif ($matchEncryptionRule)
    {
        Write-Verbose -message "[$($MyInvocation.MyCommand.Name)] : $true"
        return $true
    }
    elseif ($matchUseCookies -and $matchSessionTimeout)
    {
        Write-Verbose -message "[$($MyInvocation.MyCommand.Name)] : $true"
        return $true
    }
    elseif ($matchMultipleKeyvaluePair.count -gt 1)
    {
        foreach ($line in $checkContent)
        {
            # Handles the specific cases that need to be split
            if ($line -match "Verify ""cookieless"" is set to ""UseCookies""")
            {
                return $true
            }
            if ($line -match "20 minutes or less")
            {
                return $true
            }
            if ($line -match "ISAPI and CGI")
            {
                return $true
            }
        }
        Write-Verbose -message "[$($MyInvocation.MyCommand.Name)] : $false"
        return $false
    }
    else
    {
        Write-Verbose -message "[$($MyInvocation.MyCommand.Name)] : $false"
        return $false
    }
}

<#
    .SYNOPSIS
        Splits a STIG setting into multiple rules when necessary.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Split-MultipleWebConfigurationPropertyRule
{
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    $splitWebConfigurationPropertyRules = @()
    $matchMultipleKeyvaluePair = $checkContent | Select-String -Pattern ([RegularExpression]::KeyValuePair) -AllMatches

    if ($checkContent -match $regularExpression.configSection)
    {
        foreach ($line in $checkContent)
        {
            if ($line -match $regularExpression.configSection)
            {
                $webConfigurationPropertyRuleConfig = @()
                $webConfigurationPropertyRuleConfig += $line
            }
            if ($line -match $regularExpression.keyValuePairLine)
            {
                $webConfigurationPropertyRule = @()
                $webConfigurationPropertyRule = $webConfigurationPropertyRuleConfig + $line
                $splitWebConfigurationPropertyRules += ($webConfigurationPropertyRule -join "`r`n")
            }
        }
    }
    elseif ($checkContent -match $regularExpression.HMACSHA256)
    {
        [Array] $webConfigurationPropertyRule = $checkContent | Where-Object -Filterscript {$PSItem -notMatch $regularExpression.HMACSHA256}

        if ($checkContent -match $regularExpression.HMACSHA256)
        {
            $match = $checkContent | Select-String -Pattern $regularExpression.HMACSHA256 -AllMatches
            $splitWebConfigurationPropertyRules += @($webConfigurationPropertyRule + $match.Matches.Groups.Value) -join "`r`n"
        }
        if ($checkContent -match $regularExpression.autoEncryptionMethod)
        {
            $match = $checkContent | Select-String -Pattern $regularExpression.autoEncryptionMethod -AllMatches
            $splitWebConfigurationPropertyRules += @($webConfigurationPropertyRule + $match.Matches.Groups.Value) -join "`r`n"
        }
    }
    elseif (($checkContent -match $regularExpression.useCookies) -and ($checkContent -match $regularExpression.expiredSession))
    {
        [Array] $webConfigurationPropertyRule = $checkContent | Where-Object -Filterscript {$PSItem -notMatch $regularExpression.useCookies -and $PSItem -notmatch $regularExpression.expiredSession}

        if ($checkContent -match $regularExpression.useCookies)
        {
            $match = $checkContent | Select-String -Pattern $regularExpression.useCookies | Select-String -NotMatch "Regenerate"
            $splitWebConfigurationPropertyRules += @($webConfigurationPropertyRule + $match.Line) -join "`r`n"
        }
        if ($checkContent -match $regularExpression.expiredSession)
        {
            $match = $checkContent | Select-String -Pattern $regularExpression.expiredSession | Select-String -NotMatch "Cookie"
            $splitWebConfigurationPropertyRules += @($webConfigurationPropertyRule + $match.Line) -join "`r`n"
        }
    }
    elseif (($checkContent -match $regularExpression.useCookies) -and ($checkContent -match $regularExpression.sessionTimeout))
    {
        [Array] $webConfigurationPropertyRule = $checkContent | Where-Object -Filterscript {$PSItem -notMatch $regularExpression.useCookies -and $PSItem -notmatch $regularExpression.sessionTimeout}

        if ($checkContent -match $regularExpression.useCookies)
        {
            $match = $checkContent | Select-String -Pattern $regularExpression.useCookies | Select-String -NotMatch "Time-out"
            $splitWebConfigurationPropertyRules += @($webConfigurationPropertyRule + $match.Line) -join "`r`n"
        }
        if ($checkContent -match $regularExpression.sessionTimeout)
        {
            $match = $checkContent | Select-String -Pattern $regularExpression.sessionTimeout -AllMatches
            $splitWebConfigurationPropertyRules += @($webConfigurationPropertyRule + $match.Line) -join "`r`n"
        }
    }
    elseif ($matchMultipleKeyvaluePair.count -gt 1)
    {
        [Array] $webConfigurationPropertyRule = $checkContent | Where-Object -Filterscript {$PSItem -notMatch $regularExpression.CGIModules -and $PSItem -notmatch $regularExpression.ISAPIModules}

        if ($checkContent -match $regularExpression.CGIModules)
        {
            $match = 'Verify the "Allow unspecified CGI modules" check box is not checked'
            $splitWebConfigurationPropertyRules += @($webConfigurationPropertyRule + $match) -join "`r`n"
        }

        if ($checkContent -match $regularExpression.ISAPIModules)
        {
            $match = 'Verify the "Allow unspecified ISAPI modules" check box is not checked'
            $splitWebConfigurationPropertyRules += @($webConfigurationPropertyRule + $match) -join "`r`n"
        }
    }
    else
    {
        Write-Error -message "[$($MyInvocation.MyCommand.Name)] failed to split rule, no RegEx match"
    }

    return $splitWebConfigurationPropertyRules
}

<#
    .SYNOPSIS
        Takes the key property from a WebConfigurationPropertyRule to determine the Organizational value.
        Tests the string to return.

    .PARAMETER Key
        Key property from the WebConfigurationPropertyRule.
#>
function Get-WebConfigOrganizationValueTestString
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Key
    )
    # TO DO - This should not be a static list
    switch ( $Key )
    {
        { $PsItem -match 'maxUrl' }
        {
            return '{0} -le 4096'
        }
        { $PsItem -match 'maxAllowedContentLength' }
        {
            return '{0} -le 30000000'
        }
        { $PsItem -match 'maxQueryString' }
        {
            return '{0} -le 2048'
        }
        { $PsItem -match 'level' }
        {
            return "'{0}' -cmatch '^(Full|High)$'"
        }
        { $PsItem -match 'timeout' }
        {
            return "'{0}' -le '00:20:00'"
        }
        default
        {
            return $null
        }
    }
}
#endregion
