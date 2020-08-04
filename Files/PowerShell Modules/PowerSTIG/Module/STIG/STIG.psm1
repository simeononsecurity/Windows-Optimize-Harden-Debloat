# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.LoadFactory.psm1
using module .\..\Rule.Skip\Skip.psm1
# Header

<#
    .SYNOPSIS
        This class describes a STIG
    .DESCRIPTION
        The STIG class describes a STIG, the collection of rules for a given
        technology that need to be implemented in order to enforce the security
        posture those rules define. STIG takes in instances of many other classes
        that describe the given technology and the implementing organizations
        specific settings, exceptions, and rules to skip. Upon creation of a
        STIG instance, the resulting Xml is immediately available for those preconditions.
    .PARAMETER StigVersion
        The document/published version of the Stig to select
    .PARAMETER Technology
        The type of the technology of the Stig to select
    .PARAMETER TechnologyRole
        The role of the technology of the Stig to select
    .PARAMETER TechnologyVersion
        The version of the technology of the Stig to select
    .PARAMETER StigXml
        The loaded Xml document of the Stig loaded from StigPath
    .PARAMETER StigPath
        The file path to the Stig Xml file in the StigData directory
    .EXAMPLE

    .NOTES
        This class requires PowerShell v5 or above.
#>

class STIG
{
    [string] $Technology # this is aligned to a DSC composite resource.
    [string] $TechnologyVersion # this is 2012R2, 2016, etc.
    [string] $TechnologyRole # this is DC, MS, Database, Instance, etc.
    [Version] $Version # this is the version of the STIG
    hidden [string] $RuleFile # the file name of the processed rule file
    [System.Collections.ArrayList] $RuleList = @() # the STIG Rules
    hidden [hashtable] $RuleIdIndex = @{} # an index into $RuleList

    static $DataPath = (Resolve-Path -Path "$($script:PSScriptRoot)\..\..\StigData\Processed").Path

    #region Constructor
    hidden [STIG] _STIG ([string] $Technology, [string] $TechnologyVersion, [string] $TechnologyRole, [Version] $Version)
    {
        $this.Technology = $Technology
        $ruleFileString = $Technology

        $this.TechnologyVersion = $TechnologyVersion
        $ruleFileString += "-$TechnologyVersion"

        if (-not [string]::IsNullOrEmpty($TechnologyRole))
        {
            $this.TechnologyRole = $TechnologyRole
            $ruleFileString += "-$TechnologyRole"
        }

        if ($null -eq $Version)
        {
            $this.Version = $this.GetLatest()
        }
        else
        {
            $this.Version = $Version
        }

        $ruleFileString += "-$($this.Version)"

        $this.RuleFile = [STIG]::DataPath + "\$ruleFileString`.xml"

        if (-not $this.Validate())
        {
            throw "$ruleFileString was not found. Please run [Stig]::ListAvailable() to view the list of avalable STIG's."
        }

        return $this
    }
    <#
        .SYNOPSIS
            DO NOT USE - For testing only

        .DESCRIPTION
            A parameterless constructor for STIG. To be used only for
            build/unit testing purposes as Pester currently requires it in order to test
            static methods on powershell classes
    #>
    STIG ()
    {
        Write-Warning "This constructor is for build testing only."
    }
    # STIG specification w/o role, return latest version or list available
    STIG ([string] $Technology, [string] $TechnologyVersion)
    {
        $this._STIG($Technology, $TechnologyVersion, $null, $null)
    }
    # Full STIG specification w/o role
    STIG ([string] $Technology, [string] $TechnologyVersion, [Version] $Version)
    {
        $this._STIG($Technology, $TechnologyVersion, $null, $Version)
    }
    # STIG specification w/ role, return latest version or list available
    STIG ([string] $Technology, [string] $TechnologyVersion, [string] $TechnologyRole)
    {
        $this._STIG($Technology, $TechnologyVersion, $TechnologyRole, $null)
    }
    # Full STIG specification w/ role
    STIG ([string] $Technology, [string] $TechnologyVersion, [string] $TechnologyRole, [Version] $Version)
    {
        $this._STIG($Technology, $TechnologyVersion, $TechnologyRole, $Version)
    }

    <#
        The validate method is used to test that the rule file exists
    #>
    [bool] Validate()
    {
        if ( Test-Path -Path $this.RuleFile )
        {
            return $true
        }
        return $false
    }
    #endregion

    #region List Available

    static hidden [STIG[]] _ListAvailable ([string] $Technology, [string] $TechnologyVersion, [string] $TechnologyRole)
    {
        $params = @{
            Path = [STIG]::DataPath
            Exclude = "*.org.default.xml"
        }

        if (-not [string]::IsNullOrEmpty($Technology))
        {
            # The trailing \* is needed for the Include paramter to work
            $params.Path = "$($params.Path)\*"
            $params.Add('Include', "$Technology-")
        }

        if (-not [string]::IsNullOrEmpty($TechnologyVersion))
        {
            $params.Include = "$($params.Include)$TechnologyVersion-"
        }

        if (-not [string]::IsNullOrEmpty($TechnologyRole))
        {
            $params.Include = "$($params.Include)$TechnologyRole-"
        }

        # add the trailing wildcard to the include file name
        $params.Include = "$($params.Include)*"
        $stigRuleFileList = Get-ChildItem @params

        $return = [System.Collections.ArrayList]@()
        foreach ($stigRuleFile in $stigRuleFileList)
        {
            $propertyList = $stigRuleFile.BaseName -split "-"

            if ($propertyList.count -eq 3)
            {
                $null = $return.Add([STIG]::new($propertyList[0], $propertyList[1], [version]$propertyList[2]))
            }
            elseif ($propertyList.Count -eq 4)
            {
                $null = $return.Add([STIG]::new($propertyList[0], $propertyList[1], $propertyList[2], $propertyList[3]))
            }
        }

        return $return
    }
    static [STIG[]] ListAvailable ()
    {
        return [STIG]::_ListAvailable($null, $null, $null)
    }
    static [STIG[]] ListAvailable ([string] $Technology)
    {
        return [STIG]::_ListAvailable($Technology, $null, $null)
    }
    static [STIG[]] ListAvailable ([string] $Technology, [string] $TechnologyVersion)
    {
        return [STIG]::_ListAvailable($Technology, $TechnologyVersion, $null)
    }
    static [STIG[]] ListAvailable ([string] $Technology, [string] $TechnologyVersion, [string] $TechnologyRole)
    {
        return [STIG]::_ListAvailable($Technology, $TechnologyVersion, $TechnologyRole)
    }
    #endregion

    #region Load Rules
    hidden [void] _LoadRules([object] $OrgSettings, [hashtable] $Exceptions, [string[]] $SkipRules, [string[]] $SkipRuleType)
    {
        [xml]$rules = [xml](Get-Content -Path $this.RuleFile)
        $overRideValues = @{}

        #region Org Settings
        # Import Org Settings xml
        if ([string]::IsNullOrEmpty($OrgSettings) -or $OrgSettings -is [hashtable])
        {
            [xml]$xmlOrgSettings = (Get-Content -Path ($this.RuleFile -replace '.xml', '.org.default.xml'))
            [hashtable]$settings = ConvertTo-OrgSettingHashtable -XmlOrgSetting $xmlOrgSettings
            if ($OrgSettings -is [hashtable])
            {
                [hashtable]$settings = Merge-OrgSettingValue -DefaultOrgSetting $settings -UserSpecifiedOrgSetting $OrgSettings
            }
        }
        else
        {
            [xml]$xmlOrgSettings = Get-Content -Path $OrgSettings
            [hashtable]$settings = ConvertTo-OrgSettingHashtable -XmlOrgSetting $xmlOrgSettings
        }

        # If there are no org settings to merge, skip over that
        if ($null -ne $settings)
        {
            foreach ($ruleId in $settings.Keys)
            {
                $ruleOverRideInformation = @{}
                $ruleOverRideProperties = $settings[$ruleId].Keys
                foreach ($ruleOverRideProperty in $ruleOverRideProperties)
                {
                    $ruleOverRideInformation[$ruleOverRideProperty] = $settings[$ruleId].$ruleOverRideProperty
                }
                $overRideValues[$ruleId] = $ruleOverRideInformation
            }
        }
        #endregion

        foreach ($type in $rules.DISASTIG.ChildNodes.GetEnumerator())
        {
            foreach ($rule in $type.Rule)
            {
                if (@($SkipRules) -contains $rule.Id -or @($SkipRuleType) -contains $type.Name)
                {
                    $importRule = [SkippedRule]::new($rule)
                }
                else
                {
                    $importRule = [LoadFactory]::Rule($rule)

                    # OrgSettings
                    if ($importRule.OrganizationValueRequired)
                    {
                        if ($overRideValues.ContainsKey($rule.Id))
                        {
                            if (-not ($overRideValues[$rule.Id].Values -contains [string]::Empty))
                            {
                                $importRule.AddOrgSetting($overRideValues[$rule.Id])
                            }
                            else
                            {
                                Write-Warning -Message "RuleId: $($rule.Id) in $($rule.ParentNode.ParentNode.stigid) contains an empty Organizational Value, setting rule as Skipped"
                                $importRule = [SkippedRule]::new($rule)
                            }
                        }
                        else
                        {
                            throw "Org Setting not found for $($rule.Id)"
                        }
                    }

                    # Exceptions Need to apply after org settings
                    if ($null -ne $Exceptions -and $Exceptions.ContainsKey($rule.Id))
                    {
                        $importRule.AddExceptionToPolicy($Exceptions[$rule.Id])
                    }
                }

                $ruleListIndex = $this.RuleList.Add($importRule)
                $this.RuleIdIndex.Add($importRule.Id, $ruleListIndex)
            }
        }
    }
    [void] LoadRules()
    {
        $this._LoadRules($null, $null, $null, $null)
    }
    [void] LoadRules([object] $OrgSettings)
    {
        $this._LoadRules($OrgSettings, $null, $null, $null)
    }
    [void] LoadRules([object] $OrgSettings, [hashtable] $Exceptions)
    {
        $this._LoadRules($OrgSettings, $Exceptions, $null, $null)
    }
    [void] LoadRules([object] $OrgSettings, [hashtable] $Exceptions, [string[]] $SkipRules)
    {
        $this._LoadRules($OrgSettings, $Exceptions, $SkipRules, $null)
    }
    [void] LoadRules([object] $OrgSettings, [hashtable] $Exceptions, [string[]] $SkipRules, [string[]] $SkipRuleType)
    {
        $this._LoadRules($OrgSettings, $Exceptions, $SkipRules, $SkipRuleType)
    }
    #endregion

    #region Help

    [string] GetExceptionHelp ([string] $RuleId)
    {
        # Get the module version from the manifest to inject into the help example
        $moduleVersion = (
            Import-PowerShellDataFile -Path $PSScriptRoot\..\..\PowerStig.psd1
        ).ModuleVersion

        # load the STIG rules if they are not already laoded
        if ($this.RuleList.Count -le 0)
        {
            $this.LoadRules()
        }

        try
        {
            $rule = $this.RuleList[$this.RuleIdIndex[$RuleId]]
        }
        catch
        {
            throw "$ruleId was not found in the currently loaded STIG."
        }

        $exceptionHelp = $rule.GetExceptionHelp()
        $return = [System.Text.StringBuilder]::new()
        $null = $return.AppendLine('')
        $null = $return.AppendLine('RULE TYPE')
        $null = $return.AppendLine("   $($rule.GetType().ToString())")
        $null = $return.AppendLine('')
        $null = $return.AppendLine('DESCRIPTION')
        $null = $return.AppendLine("   The $($rule.GetType().ToString()) property '$($rule.GetOverrideValue())' can be overridden ")
        $null = $return.AppendLine('   with an exception using the syntax below.')
        $null = $return.AppendLine('')
        if ($null -ne $exceptionHelp.Notes)
        {
            $null = $return.AppendLine('NOTES')
            $null = $return.AppendLine("   $($exceptionHelp.Notes)")
            $null = $return.AppendLine('')
        }
        $null = $return.AppendLine('SAMPLE CONFIGURATION')
        $null = $return.AppendLine('')
        $null = $return.AppendLine('configuration Sample')
        $null = $return.AppendLine('{')
        $null = $return.AppendLine("    Import-DscResource -ModuleName PowerStig -ModuleVersion $moduleVersion")
        $null = $return.AppendLine('')
        $null = $return.AppendLine('    Node $NodeName')
        $null = $return.AppendLine('    {')
        $null = $return.AppendLine("        $($this.Technology) BaseLine")
        $null = $return.AppendLine('        {')
        $null = $return.AppendLine("            OsVersion   = '$($this.TechnologyVersion)'")
        $null = $return.AppendLine("            OsRole      = '$($this.TechnologyRole)'")
        $null = $return.AppendLine("            StigVersion = '$($this.Version)'")
        $null = $return.AppendLine("            Exception   = @{'$($rule.id)' = '$($exceptionHelp.value)'}")
        $null = $return.AppendLine('        }')
        $null = $return.AppendLine('    }')
        $null = $return.AppendLine('}')

        return $return.ToString()
    }

    #endregion

    <#
        .SYNOPSIS
            Returns the highest available Stig version
        .DESCRIPTION
            Returns the highest available Stig version for a given Technology, TechnologyVersion, and TechnologyRole
    #>
    [version] GetLatest ()
    {
        $stigList = [STIG]::ListAvailable(
            $this.Technology, $this.TechnologyVersion, $this.TechnologyRole)

        $maximumStigVersion = (
            $stigList | Measure-Object -Maximum -Property Version).Maximum

        return [version]::new($maximumStigVersion)
    }
}

# Footer
$exclude = @($MyInvocation.MyCommand.Name,'Template.*.txt', '*.md')
foreach ($supportFile in Get-ChildItem -Path $PSScriptRoot -File -Exclude $exclude)
{
    Write-Verbose "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}
Export-ModuleMember -Function '*' -Variable '*'

