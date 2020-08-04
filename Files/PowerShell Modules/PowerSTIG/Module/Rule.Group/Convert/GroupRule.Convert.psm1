# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\GroupRule.psm1

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
        Convert the contents of an xccdf check-content element into a group object
    .DESCRIPTION
        The GroupRuleConvert class is used to extract the group membership settings
        from the check-content of the xccdf. Once a STIG rule is identified as a
        group rule, it is passed to the GroupRuleConvert class for parsing
        and validation.
#>
class GroupRuleConvert : GroupRule
{
    <#
        .SYNOPSIS
        Empty constructor for SplitFactory
    #>
    GroupRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf stig rule element into a Group Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    GroupRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $this.SetGroupName()
        $this.SetMembersToExclude()

        if ($this.conversionstatus -eq 'pass')
        {
            $this.SetDuplicateRule()
        }

        $this.SetDscResource()
    }

    #region Methods

    <#
        .SYNOPSIS
            Extracts the group name from the check-content and sets the value
        .DESCRIPTION
            Gets the group name from the xccdf content and sets the value. If
            the group that is returned is not a valid name, the parser status
            is set to fail.
    #>
    [void] SetGroupName ()
    {
        $thisGroupDetails = Get-GroupDetail -CheckContent $this.rawString

        if (-not $this.SetStatus($thisGroupDetails.GroupName))
        {
            $this.set_GroupName($thisGroupDetails.GroupName)
        }
    }

    <#
        .SYNOPSIS
            Extracts the list of group names from the check-content and sets the value
        .DESCRIPTION
            Gets the list of group name from the xccdf content and sets the value.
            If the list that is returned is not a valid, the parser status is
            set to fail
    #>
    [void] SetMembersToExclude ()
    {
        if ($this.rawString -match 'Domain Admins group must be replaced')
        {
            $thisGroupMember = (Get-GroupDetail -CheckContent $this.rawString).Members
        }
        else
        {
            $thisGroupMember = $null
        }
        if (-not $this.SetStatus($thisGroupMember))
        {
            $this.set_MembersToExclude($thisGroupMember)
        }
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'Group'
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
            $CheckContent -Match 'Navigate to System Tools >> Local Users and Groups >> Groups\.' -and
            $CheckContent -NotMatch 'Backup Operators|Hyper-V Administrators' -and
            $CheckContent -NotMatch 'domain-joined workstations, the Domain Admins'
        )
        {
            return $true
        }
        return $false
    }
    #endregion
}
