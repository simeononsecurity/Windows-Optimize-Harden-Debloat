# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
    .SYNOPSIS
        Gets the User Rights Assignment Display Name from the check-content that are assigned to
        the User Rights Assignment policy
#>
function Get-UserRightDisplayName
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    # Use a regular expression to pull the userright string from between the quotes
    $userRightDisplayNameSearch = ( $checkContent |
        Select-String -Pattern ([RegularExpression]::TextBetweenQuotes) -AllMatches )

    [string[]] $userRightDisplayName = $userRightDisplayNameSearch.matches.Groups.Value |
        Where-Object { $userRightNameToConstant.Keys -contains $PSItem }

    if ( $null -ne $userRightDisplayName )
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] UserRightDisplayName : $UserRightDisplayName "
        return $userRightDisplayName[0]
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] UserRightDisplayName : Not Found"
    }
}

<#
    .SYNOPSIS
        Enumerates User Rights Assignment Policy display names and converts them to the matching constant
#>
function Get-UserRightConstant
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $UserRightDisplayName
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    $userRightConstant = $userRightNameToConstant.$UserRightDisplayName

    if ( $null -ne $userRightConstant )
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Found: $UserRightDisplayName : $userRightConstant "
        $userRightConstant
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Not Found : $UserRightDisplayName "
    }
}

<#
    .SYNOPSIS
        Gets the Identity from the check-content that are assigned to the User Rights Assignment policy
#>
function Get-UserRightIdentity
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"
    <#
        Select the line that contains the User Right
        one entry contains multiple lines with the same user right so select the first index
    #>

    $return = [System.Collections.ArrayList] @()

    if ($checkContent -Match "Administrators\sAuditors\s" -and $checkContent -Match "DNS\sServer\slog\sfile" )
    {
        [void] $return.Add('Administrators')
    }
    elseif ($checkContent -Match "If (any|the following){1} (accounts or groups|groups or accounts) (other than the following|are not defined){1}.*this is a finding")
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Ensure : Present"
        # There is an edge case where multiple finding statements are made, so a zero index is needed.
        [int] $lineNumber = (($checkContent | Select-String "this is a finding")[0]).LineNumber
        # Set the negative index number of the first group to process.
        $startLine = $lineNumber - $checkContent.Count

        foreach ($line in $checkContent[$startLine..-1])
        {
            <#
                The Windows Server 2016 STIG prepends each identity with a dash space (- )
                that needs to be trimmed from the results before they are returned.
            #>
            $line = $line -replace '^\s*-\s*', ''

            if
            (
                $line.Trim() -notmatch ":|^If|^Microsoft|^Organizations|^Vendor|^The|^(Systems|Workstations)\sDedicated|Privileged Access" -and
                -not [string]::IsNullOrEmpty( $line.Trim() )
            )
            {
                <#
                    There are a few entries that add the word 'group' to the end of the group name, so
                    they need to be cleaned up.
                #>
                if ($line.Trim() -match "Hyper-V")
                {
                    [void] $return.Add("{Hyper-V}")
                }
                elseif ($line.Trim() -match "(^Enterprise|^Domain) (Admins|Admin)|^Guests")
                {
                    if ($line -match '\sAdmin\s')
                    {
                        $line = $line -replace 'Admin', 'Admins'
                    }
                    # .Trim method is case sensitive, so the replace operator is used instead
                    [void] $return.Add($($line.Trim() -replace ' Group').Trim())
                }
                elseif ($line.Trim() -match '"Local account and member of Administrators group" or "Local account"')
                {
                    [void] $return.Add('(Local account and member of Administrators group|Local account)')
                }
                else
                {
                    <#
                        The below regex with remove anything between parentheses.
                        This address the edge case where parentheses are used to add a note following the identity
                    #>
                    [void] $return.Add( ($line -replace '\([\s\S]*?\)').Trim() )
                }
            }
        }
    }
    elseif ($checkContent -Match "If any (accounts or groups|groups or accounts).*are (granted|defined).*this is a finding")
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Ensure : Absent"

        [void] $return.Add("NULL")
    }

    $return
}

<#
    .SYNOPSIS
        Looks in the Check-Content element to see if it matches any scrict User Rights Assignments.
#>
function Test-SetForceFlag
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]
        $CheckContent
    )

    if ($checkContent -match 'If any (accounts or groups|groups or accounts) other than the following')
    {
        return $true
    }
    elseif ($checkContent -match 'If any (accounts or groups|groups or accounts)\s*(\(.*\),)?\s*are (granted|defined)')
    {
        return $true
    }

    return $false
}

<#
    .SYNOPSIS
        Supports the ContainsMultipleRules statis method to test for multiple
        user rights assignment rules
#>
function Test-MultipleUserRightsAssignment
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

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    $userRightMatches = $checkContent | Select-String -Pattern 'local computer policy'

    if ( $userRightMatches.count -gt 1 )
    {
        return $true
    }

    return $false
}

<#
    .SYNOPSIS
        Parses STIG check-content to return text pertaining to individual UserRightAssignment rules
#>
function Split-MultipleUserRightsAssignment
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    $userRightMatches = $checkContent | Select-String -Pattern 'local computer policy'
    $i = 1
    foreach ( $match in $userRightMatches )
    {
        $stringBuilder = New-Object System.Text.StringBuilder
        if ($i -ne $userRightMatches.count)
        {
            [string[]] $content = $checkContent[($match.lineNumber)..($userRightMatches[$i].lineNumber - 2 )]
        }
        else
        {
            [string[]] $content = $checkContent[($match.lineNumber)..$checkContent.Length]
        }

        foreach ( $line in $content  )
        {
            [void] $stringBuilder.Append("$line`r`n")
        }
        $i++
        $stringBuilder.ToString()
    }
}
#endregion
