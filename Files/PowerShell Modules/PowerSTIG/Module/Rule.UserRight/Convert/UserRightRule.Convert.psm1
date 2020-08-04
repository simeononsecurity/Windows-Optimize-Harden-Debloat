# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\UserRightRule.psm1

$exclude = @($MyInvocation.MyCommand.Name,'Template.*.txt')
$supportFileList = Get-ChildItem -Path $PSScriptRoot -Exclude $exclude
foreach ($supportFile in $supportFileList)
{
    Write-Verbose "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}
# Header

<#
    .SYNOPSIS
        Convert the contents of an xccdf check-content element into a user right object
    .DESCRIPTION
        The UserRightRule class is used to extract the {} settings from the
        check-content of the xccdf. Once a STIG rule is identified a
        user right rule, it is passed to the UserRightRule class for parsing
        and validation.
#>
class UserRightRuleConvert : UserRightRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    UserRightRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf STIG rule element into a User Right Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    UserRightRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $this.SetDisplayName()
        $this.SetConstant()
        $this.SetIdentity()
        $this.SetForce()
        $this.SetDuplicateRule()
        if (Test-ExistingRule -RuleCollection $global:stigSettings -NewRule $this)
        {
            $this.set_id((Get-AvailableId -Id $this.Id))
        }
        $this.SetDscResource()
    }

    #region Methods

    <#
        .SYNOPSIS
            Extracts the display name from the check-content and sets the value
        .DESCRIPTION
            Gets the display name from the xccdf content and sets the value. If
            the name that is returned is not valid, the parser status is set to fail.
    #>
    [void] SetDisplayName ()
    {
        $thisDisplayName = Get-UserRightDisplayName -CheckContent $this.SplitCheckContent

        if (-not $this.SetStatus($thisDisplayName))
        {
            $this.set_DisplayName($thisDisplayName)
        }
    }

    <#
        .SYNOPSIS
            Extracts the user right constant from the check-content and sets the value
        .DESCRIPTION
            Gets the user right constant from the xccdf content and sets the
            value. If the constant that is returned is not valid, the parser
            status is set to fail.
    #>
    [void] SetConstant ()
    {
        $thisConstant = Get-UserRightConstant -UserRightDisplayName $this.DisplayName

        if (-not $this.SetStatus($thisConstant))
        {
            $this.set_Constant($thisConstant)
        }
    }

    <#
        .SYNOPSIS
            Extracts the user right identity from the check-content and sets the value
        .DESCRIPTION
            Gets the user right identity from the xccdf content and sets the
            value. If the identity that is returned is not valid, the parser
            status is set to fail.
    #>
    [void] SetIdentity ()
    {
        $thisIdentity = Get-UserRightIdentity -CheckContent $this.SplitCheckContent
        $return = $true
        if ([String]::IsNullOrEmpty($thisIdentity))
        {
            $return = $false
        }
        elseif ($thisIdentity -ne 'NULL')
        {
            if ($thisIdentity -join "," -match "{Hyper-V}")
            {
                $this.SetOrganizationValueRequired()
                $HyperVIdentity = $thisIdentity -join "," -replace "{Hyper-V}", "NT Virtual Machine\\Virtual Machines"
                $NoHyperVIdentity = $thisIdentity.Where( {$PSItem -ne "{Hyper-V}"}) -join ","
                $this.set_OrganizationValueTestString("'{0}' -match '^($HyperVIdentity|$NoHyperVIdentity)$'")
            }
            elseif ($thisIdentity -contains "(Local account and member of Administrators group|Local account)")
            {
                $this.SetOrganizationValueRequired()
                $this.set_OrganizationValueTestString("'{0}' -match '$($thisIdentity -join ",")'")
            }
        }

        if ($this.OrganizationValueRequired -eq $false)
        {
            $this.Identity = $thisIdentity -Join ","
        }
    }

    <#
        .SYNOPSIS
            Extracts the force flag from the check-content and sets the value
        .DESCRIPTION
            Gets the force flag from the xccdf content and sets the value
    #>
    [void] SetForce ()
    {
        if (Test-SetForceFlag -CheckContent $this.SplitCheckContent)
        {
            $this.set_Force($true)
        }
        else
        {
            $this.set_Force($false)
        }
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'UserRightsAssignment'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if
        (
            $CheckContent -Match 'gpedit\.msc' -and
            $CheckContent -Match 'User Rights Assignment' -and
            $CheckContent -NotMatch 'unresolved SIDs' -and
            $CheckContent -NotMatch 'SQL Server'
        )
        {
            return $true
        }
        return $false
    }

    <#
        .SYNOPSIS
            Tests if a rule contains multiple checks
        .DESCRIPTION
            Search the rule text to determine if multiple user rights are defined
        .PARAMETER CheckContent
            The rule text from the check-content element in the xccdf
    #>
    <#{TODO}#> # HasMultipleRules is implemented inconsistently.
    static [bool] HasMultipleRules ([string] $CheckContent)
    {
        if (Test-MultipleUserRightsAssignment -CheckContent ([UserRightRule]::SplitCheckContent($CheckContent)))
        {
            return $true
        }

        return $false
    }

    <#
        .SYNOPSIS
            Splits a rule into multiple checks
        .DESCRIPTION
            Once a rule has been found to have multiple checks, the rule needs
            to be split. This method splits a user right into multiple rules. Each
            split rule id is appended with a dot and letter to keep reporting
            per the ID consistent. An example would be is V-1000 contained 2
            checks, then SplitMultipleRules would return 2 objects with rule ids
            V-1000.a and V-1000.b
        .PARAMETER CheckContent
            The rule text from the check-content element in the xccdf
    #>
    static [string[]] SplitMultipleRules ([string] $CheckContent)
    {
        return (Split-MultipleUserRightsAssignment -CheckContent ([UserRightRule]::SplitCheckContent($CheckContent)))
    }

    #endregion
}
