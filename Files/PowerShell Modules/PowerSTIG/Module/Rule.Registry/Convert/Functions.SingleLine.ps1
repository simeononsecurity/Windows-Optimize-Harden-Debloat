# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Main Functions
<#
    .SYNOPSIS
        Looks in the Check-Content element to see if it matches registry string.

    .PARAMETER CheckStrings
        Check-Content element
#>
function Test-SingleLineRegistryRule
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    if ($checkContent -match "(HKCU|HKLM|HKEY_LOCAL_MACHINE)\\")
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $true"
        $true
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $false"
        $false
    }
}
#endregion
#region Registry Path
<#
    .SYNOPSIS
        Extract the registry path from an office STIG string.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-SingleLineRegistryPath
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    foreach ($item in $global:SingleLineRegistryPath.Values)
    {
        $value = Get-SLRegistryPath -CheckContent $CheckContent -Hashtable $item
        if ([String]::IsNullOrEmpty($value) -eq $false)
        {
            return $value | where-object {[string]::IsNullOrEmpty($_) -eq $false}
        }
    }
}

<#
    .SYNOPSIS
        Extract the registry path from an office STIG string.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.

    .PARAMETER Hashtable
        The $SingleLineRegistryPath table taken from the Data.*.ps1 file(s).
#>
function Get-SLRegistryPath
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter(Mandatory = $true)]
        [psobject]
        $Hashtable
    )

    $fullRegistryPath = $CheckContent

    foreach ($key in $Hashtable.Keys)
    {
        if ($Hashtable.Item($key).GetType().Name -eq 'OrderedDictionary')
        {
            $innerValue = Get-SLRegistryPath -CheckContent $fullRegistryPath -Hashtable $Hashtable.Item($key)
            if ($innerValue)
            {
                return $innerValue
            }

            continue
        }
        else
        {
            switch ($key)
            {
                Contains
                {
                    if (@($fullRegistryPath | Where-Object { $_.ToString().Contains($Hashtable.Item($key))}).Count -gt 0)
                    {
                        continue
                    }
                    else
                    {
                        return
                    }
                }
                Match
                {
                    if ($fullRegistryPath -match $Hashtable.Item($key))
                    {
                        continue
                    }
                    else
                    {
                        return
                    }
                }
                Select
                {
                    $regEx = '{0}' -f $Hashtable.Item($key)
                    $selectedRegistryPath = $CheckContent | Select-String -Pattern $regEx
                    if ([string]::IsNullOrEmpty($selectedRegistryPath))
                    {
                        $matchedRegistryPath = $selectedRegistryPath
                    }
                    else
                    {
                        $matchedRegistryPath = $selectedRegistryPath.Matches[0].Value
                    }
                }
            }
        }
    }

    if (-not [String]::IsNullOrEmpty($matchedRegistryPath))
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Found path : $true"
        switch -Wildcard ($matchedRegistryPath)
        {
            "*HKLM*" {$matchedRegistryPath = $matchedRegistryPath -replace "^HKLM", "HKEY_LOCAL_MACHINE"}

            "*HKCU*" {$matchedRegistryPath = $matchedRegistryPath -replace "^HKCU", "HKEY_CURRENT_USER"}

            "*Software Publishing Criteria" {$matchedRegistryPath = $matchedRegistryPath -replace 'Software Publishing Criteria$','Software Publishing'}
        }

        $result = $matchedRegistryPath.ToString().trim(' ', '.')

        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Trimmed path : $result"
        Set-RegistryPatternLog -Pattern $regEx
        return $result
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Found path : $false"
        Write-Verbose "Registry path was not found in check content."
        return
    }
}
#endregion
#region Registry Type
<#
    .SYNOPSIS
        Extract the registry value type from an Office STIG string.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-RegistryValueTypeFromSingleLineStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    foreach ($item in $global:SingleLineRegistryValueType.Values)
    {
        $value = Get-RegistryValueTypeFromSLStig -CheckContent $CheckContent -Hashtable $item
        if ([String]::IsNullOrEmpty($value) -eq $false)
        {
            return $value
        }
    }
}
<#
    .SYNOPSIS
        Extract the registry path from an McAfee STIG string.
    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-McAfeeRegistryPath
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    if ($CheckContent -match "Software\\McAfee")
    {
        $path = "HKEY_LOCAL_MACHINE\Software\Wow6432Node\McAfee\"
        if ($CheckContent -match 'DesktopProtection')
        {
            $mcafeePath = $CheckContent | Select-String -Pattern 'DesktopProtection.*$'
        }
        else
        {
            $mcafeePath = $CheckContent | Select-String -Pattern 'SystemCore.*$'
        }

        $fullyQualifiedMcAfeePath = Join-Path -Path $path -ChildPath $mcafeePath.Matches.Value
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Found registry path : $paths"
        return $fullyQualifiedMcAfeePath
    }
}

<#
    .SYNOPSIS
        Extract the registry value type from an Office STIG string.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.

    .PARAMETER Hashtable
        The $SingleLineRegistryValueType table taken from the Data.*.ps1 file(s).
#>
function Get-RegistryValueTypeFromSLStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter(Mandatory = $true)]
        [psobject]
        $Hashtable
    )

    $valueName = Get-RegistryValueNameFromSingleLineStig -CheckContent $CheckContent

    # McAfee STIG isn't written in a way that ValueType can be detected via CheckContent and/or FixText
    if ($CheckContent -match 'Wow6432Node\\McAfee')
    {
        $valueType = 'DWORD'
    }
    else
    {
        foreach ($key in $Hashtable.Keys)
        {
            switch ($key)
            {
                Contains
                {
                    if (@($fullRegistryPath | Where-Object {$_.ToString().Contains($Hashtable.Item($key))}).Count -gt 0)
                    {
                        continue
                    }
                    else
                    {
                        return
                    }
                }
                Match
                {
                    $regEx = $Hashtable.Item($key) -f [regex]::escape($valueName)
                    $matchedValueType = [regex]::Matches($CheckContent.ToString(), $regEx)

                    if (-not $matchedValueType)
                    {
                        continue
                    }
                    else
                    {
                        return $null
                    }
                }
                Select
                {
                    if ($valueName)
                    {
                        $regEx = $Hashtable.Item($key) -f [regex]::escape($valueName)
                        $selectedValueType = Select-String -InputObject $CheckContent -Pattern $regEx
                    }

                    if (-not $selectedValueType.Matches)
                    {
                        return
                    }
                    else
                    {
                        $valueType = $selectedValueType.Matches[0].Value

                        if ($Hashtable.Item('Group'))
                        {
                            $valueType = $selectedValueType.Matches.Groups[$Hashtable.Item('Group')].Value
                        }

                        Set-RegistryPatternLog -Pattern $Hashtable.Item($key)
                    }
                }
            }
        }
    }

    if ($valueType)
    {
        $valueType = $valueType.Replace('=', '').Replace('"', '')

        if (-not [String]::IsNullOrWhiteSpace($valueType.Trim()))
        {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Found Type : $valueType"

            $valueType = Test-RegistryValueType -TestValueType $valueType

            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Converted Type : $valueType"
            return $valueType.trim()
        }
        else
        {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Found Type : $false"
            return
        }
    }
}
#endregion
#region Registry Name
<#
    .SYNOPSIS
        Extract the registry value type from a string.

    .PARAMETER CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueNameFromSingleLineStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    foreach ($item in $global:SingleLineRegistryValueName.Values)
    {
        $value = Get-RegistryValueNameFromSLStig -CheckContent $CheckContent -Hashtable $item
        if ([String]::IsNullOrEmpty($value) -eq $false)
        {
            return $value
        }
    }
}
<#
    .SYNOPSIS
        Extract the registry value type from a string.

    .PARAMETER CheckContent
        An array of the raw sting data taken from the STIG setting.

    .PARAMETER Hashtable
        The $SingleLineRegistryValueName table taken from the Data.*.ps1 file(s).
#>
function Get-RegistryValueNameFromSLStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter(Mandatory = $true)]
        [psobject]
        $Hashtable
    )

    $valueName = $CheckContent

    foreach ($key in $Hashtable.Keys)
    {
        switch ($key)
        {
            Contains
            {
                if (@($CheckContent | Where-Object { $_.ToString().Contains($Hashtable.Item($key))}).Count -gt 0)
                {
                    continue
                }
                else
                {
                    return
                }
            }
            Match
            {
                if ($CheckContent -match $Hashtable.Item($key))
                {
                  continue
                }
                else
                {
                    return
                }
            }
            Select
            {
                $regEx = '{0}' -f $Hashtable.Item($key)
                $valueName = Select-String -InputObject $CheckContent -Pattern $regEx
            }
        } # Switch
    } # Foreach

    if ($valueName)
    {
        $valueName = $valueName.Matches.Value -replace '[\u201C\u201D]|["���]', ''

        if ($valueName.Count -gt 1)
        {
            $valueName = $valueName[0]
        }

        $result = $valueName.trim()
        Set-RegistryPatternLog -Pattern $regEx

        if (-not [String]::IsNullOrEmpty($result))
        {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Found Name : $result"
            return $result
        }
        else
        {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Found Name : $false"
            return
        }
    }
}
#endregion
#region Registry Data
<#
    .SYNOPSIS
        Looks for multiple patterns in the value string to extract out the value to return or determine
        if additional processing is required. For example if an allowable range detected, additional
        functions need to be called to convert the text into powershell operators.

    .PARAMETER CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueDataFromSingleStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    foreach ($item in $global:SingleLineRegistryValueData.Values)
    {
        $value = Get-RegistryValueDataFromSLStig -CheckContent $CheckContent -Hashtable $item
        if ([String]::IsNullOrEmpty($value) -eq $false)
        {
            return $value
        }
    }
}

<#
    .SYNOPSIS
        Looks for multiple patterns in the value string to extract out the value to return or determine
        if additional processing is required. For example if an allowable range detected, additional
        functions need to be called to convert the text into powershell operators.

    .PARAMETER CheckContent
        An array of the raw sting data taken from the STIG setting.

    .PARAMETER Hashtable
        The $SingleLineRegistryValueData table taken from the Data.*.ps1 file(s).
#>
function Get-RegistryValueDataFromSLStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter(Mandatory = $true)]
        [psobject]
        $Hashtable
    )

    $valueType = Get-RegistryValueTypeFromSingleLineStig -CheckContent $CheckContent

    if ($valueType -eq "Does Not Exist")
    {
        return
    }

    foreach ($key in $Hashtable.Keys)
    {
        switch ($key)
        {
            Contains
            {
                if (@($CheckContent | Where-Object { $_.ToString().Contains($Hashtable.Item($key))}).Count -gt 0)
                {
                    continue
                }
                else
                {
                    return
                }
            }
            Match
            {
                if ($CheckContent -match $Hashtable.Item($key))
                {
                    continue
                }
                else
                {
                    return
                }
            }
            Select
            {
                $regEx = $Hashtable.Item($key) -f [regex]::escape($valueType)
                $result = $CheckContent | Select-String -Pattern $regEx

                if ($result.Count -gt 0)
                {
                    $valueData = $result[0]
                    Set-RegistryPatternLog -Pattern $Hashtable.Item($key)
                }
            }
        } # Switch
    } # Foreach

    if ($valueData.Matches)
    {
        $test = $valueData.Matches[0].Value.Replace('=', '').Replace('"', '')
        $valueData = $test.Replace(',', '').Replace('"', '')
        $result = $valueData.ToString().Trim(' ')

        if (-not [String]::IsNullOrEmpty($result))
        {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Found Name : $result"
            return $result
        }
        else
        {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Found Name : $false"
            return
        }
    }
}
#endregion
#region Ancillary functions
<#
    .SYNOPSIS
        Get the registry value string from the Office STIG format.

    .PARAMETER CheckContent
        An array of the raw sting data taken from the STIG setting.

    .PARAMETER Trim
        Trims the leading a trailing parts of the string that are not registry specific
#>
function Get-RegistryValueStringFromSingleLineStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter()]
        [switch]
        $Trim
    )

    [string] $registryLine = Select-String -InputObject $CheckContent -Pattern "Criteria:"

    if (-not [String]::IsNullOrEmpty($registryLine))
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Found Value : $true"
        $return = $registryLine.trim()
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Found Value : $false"
        return
    }

    if ($trim)
    {
        <#
            Trim leading and trailing string that is not needed.
            Criteria: If the value of excel.exe is REG_DWORD = 1, this is not a finding.
            Criteria: If the value SomeValueNAme is REG_DWORD = 1, this is not a finding.
        #>
        $return = $return -Replace "Criteria: If the value (of)*\s*|\s*,\s*this is not a finding.", ''

        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Trimmed Value : $return"
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Trimmed Value : $return"
    }

    # The string returned from here is split on the space, so remove extra spaces.
    $return -replace "\s{2,}", " "
}

<#
    .SYNOPSIS
        Checks the registry string format to determine if it is in the Office STIG format.

    .PARAMETER CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Test-SingleLineStigFormat
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    if ($checkContent -match "HKLM|HKCU|HKEY_LOCAL_MACHINE\\")
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $true"
        $true
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $false"
        $false
    }
}
#endregion
