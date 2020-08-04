# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Main Function
<#
    .SYNOPSIS
        Identifies the type of STIG that has been input and selects the proper private function to
        further convert the STIG strings into usable objects.

    .DESCRIPTION
        This function enables the core translation of the raw xccdf file by reading the benchmark
        title property to determine where to send the data for processing.

        When a ruleset match is found, the xccdf data is sent to private functions that are
        dedicated to processing individual STIG setting types, such as registry settings or
        security policy.

        If the function is unable to find a rule set match, an error is returned.

    .PARAMETER Path
        The path to the xccdf file to be processed.

    .PARAMETER IncludeRawString
        This will add the 'Check-Content' from the xcccdf to the output for any additional validation
        or spot checking that may be needed.

    .PARAMETER RuleIdFilter
        Filters the list rules that are converted to simplify debugging the conversion process.

    .EXAMPLE
        ConvertFrom-StigXccdf -Path C:\Stig\U_Windows_2012_and_2012_R2_MS_STIG_V2R8_Manual-xccdf.xml

    .OUTPUTS
        Custom objects are created from the STIG base class that are provided in the module

    .NOTES
        This is an ongoing project that should be retested with each iteration of the STIG. This is
        due to the non-standard way, the content is published. Each version of the STIG may require
        a rule to be updated to account for a new string format. All the formatting rules are heavily
        tested, so making changes is a simple task.

    .LINK
        http://iase.disa.mil/stigs/Lists/stigs-masterlist/AllItems.aspx
#>
function ConvertFrom-StigXccdf
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string[]]
        $RuleIdFilter
    )

    # Get the xml data from the file path provided.
    $stigBenchmarkXml = Get-StigXccdfBenchmarkContent -Path $path

    # Global variable needed to distinguish between the IIS server and site stigs. Server Stig needs xIISLogging resource, Site Stig needs xWebsite
    $global:stigTitle = $stigBenchmarkXml.title

    # Global variable needed to set and get specific logic needed for filtering and parsing FileContentRules
    switch ($true)
    {
        {$global:stigXccdfName -and -join ((Split-Path -Path $path -Leaf).Split('_') | Select-Object -Index (1, 2)) -eq ''}
        {
            break;
        }
        {!$global:stigXccdfName -or $global:stigXccdfName -ne -join ((Split-Path -Path $path -Leaf).Split('_') | Select-Object -Index (1, 2))}
        {
            $global:stigXccdfName = -join ((Split-Path -Path $path -Leaf).Split('_') | Select-Object -Index (1, 2))
            break;
        }
    }
    # Read in the root stig data from the xml additional functions will dig in deeper
    $stigRuleParams = @{
        StigGroupListChangeLog = Get-RuleChangeLog -Path $Path
    }

    if ($RuleIdFilter)
    {
        $stigRuleParams.StigGroupList = $stigBenchmarkXml.Group | Where-Object {$RuleIdFilter -contains $PSItem.Id}
    }
    else
    {
        $stigRuleParams.StigGroupList = $stigBenchmarkXml.Group
    }

    # The benchmark title drives the rest of the function and must exist to continue.
    if ( $null -eq $stigBenchmarkXml.title )
    {
        Write-Error -Message 'The Benchmark title property is null. Unable to determine ruleset target.'
        return
    }

    Get-RegistryRuleExpressions -Path $Path -StigBenchmarkXml $stigBenchmarkXml

    return Get-StigRuleList @stigRuleParams
}

<#
    .SYNOPSIS
        Loads the regular expressions files

    .DESCRIPTION
        This function loads the regular expression sets to process registry rules in the xccdf file.

    .PARAMETER Path
        The path to the xccdf file to be processed.

    .PARAMETER StigBenchmarkXml
        The xml for the xccdf file to be processed.
#>
function Get-RegistryRuleExpressions
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter(Mandatory = $true)]
        [object]
        $StigBenchmarkXml
    )

    begin
    {
        # Use $stigBenchmarkXml.id to determine the stig file
        $benchmarkId = Split-BenchmarkId -Id $StigBenchmarkXml.id -FilePath $Path
        if ([string]::IsNullOrEmpty($benchmarkId.TechnologyRole))
        {
            $benchmarkId.TechnologyRole = $StigBenchmarkXml.id
        }

        # Handles testing and production
        $xccdfFileName = Split-Path $Path -Leaf
        $spInclude = @('Data.Core.ps1')
        if ($xccdfFileName -eq 'TextData.xml')
        {
            # Query TechnologyRole and map to file
            $officeApps = @('Outlook', 'Excel', 'PowerPoint', 'Word')
            $mcafeeApps = @('VirusScan')
            $spExclude = @($MyInvocation.MyCommand.Name, 'Template.*.txt', 'Data.ps1', 'Functions.*.ps1', 'Methods.ps1')

            switch ($benchmarkId.TechnologyRole)
            {
                { $null -ne ($officeApps | Where-Object { $benchmarkId.TechnologyRole -match $_ }) }
                {
                    $spInclude += "Data.Office.ps1"
                }
                { $null -ne ($mcafeeApps | Where-Object { $benchmarkId.TechnologyRole -match $_ }) }
                {
                    $spInclude += "Data.Mcafee.ps1"
                }

            }
        }
        else
        {
            # Query directory of xccdf file
            $spResult = Split-Path (Split-Path $Path -Parent) -Leaf
            if ($spResult)
            {
                $spInclude += "Data." + $spResult + ".ps1"
            }
        }
    }

    process
    {
        # Load specific and core expression sets
        $childItemParams = @{
            Path = "$PSScriptRoot\..\..\Rule\Convert"
            Exclude = $spExclude
            Include = $spInclude
            Recurse = $true
        }

        $spSupportFileList = Get-ChildItem @childItemParams | Sort-Object -Descending
        Clear-Variable SingleLine* -Scope Global
        foreach ($supportFile in $spSupportFileList)
        {
            Write-Verbose "Loading $($supportFile.FullName)"
            . $supportFile.FullName
        }
    }
}

<#
    .SYNOPSIS
        This function generates a new xml file based on the convert objects from ConvertFrom-StigXccdf.
    .PARAMETER Path
        The full path to the xccdf to convert.
    .PARAMETER Destination
        The full path to save the converted xml to.
    .PARAMETER CreateOrgSettingsFile
        Creates the orginazational settings files associated with the version of the STIG.
    .PARAMETER DoNotExportRawString
        Excludes the check-content elemet content from the converted object.
    .PARAMETER RuleIdFilter
        Filters the list rules that are converted to simplify debugging the conversion process.
    .PARAMETER DoNotExportDescription
        Excludes the Description elemet content from the converted object.
#>
function ConvertTo-PowerStigXml
{
    [CmdletBinding()]
    [OutputType([xml])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Destination,

        [Parameter()]
        [switch]
        $CreateOrgSettingsFile,

        [Parameter()]
        [switch]
        $DoNotExportRawString,

        [Parameter()]
        [string[]]
        $RuleIdFilter,

        [Parameter()]
        [switch]
        $DoNotExportDescription
    )

    begin
    {
        $CurrentVerbosePreference = $global:VerbosePreference

        if ($PSBoundParameters.ContainsKey('Verbose'))
        {
            $global:VerbosePreference = 'Continue'
        }
    }
    process
    {
        $convertedStigObjects = ConvertFrom-StigXccdf -Path $Path -RuleIdFilter $RuleIdFilter

        # Get the raw xccdf xml to pull additional details from the root node.
        [xml] $xccdfXml = Get-Content -Path $Path -Encoding UTF8
        [version] $stigVersionNumber = Get-StigVersionNumber -StigDetails $xccdfXml

        $ruleTypeList = Get-RuleTypeList -StigSettings $convertedStigObjects

        # Start the XML doc and add the root element
        $xmlDocument = [System.XML.XMLDocument]::New()
        [System.XML.XMLElement] $xmlRoot = $xmlDocument.CreateElement( 'DISASTIG' )

        <#
            Append as child to an existing node. This method will 'leak' an object out of the function
            so DO NOT remove the [void]
        #>
        [void] $xmlDocument.appendChild( $xmlRoot )
        $xmlRoot.SetAttribute( 'version' , $xccdfXml.Benchmark.version )
        $xmlRoot.SetAttribute( 'classification', 'UNCLASSIFIED' )
        $xmlRoot.SetAttribute( 'customname' , '' )
        $xmlRoot.SetAttribute( 'stigid' , $xccdfXml.Benchmark.ID )
        $xmlRoot.SetAttribute( 'description' , $xccdfXml.Benchmark.description )
        $xmlRoot.SetAttribute( 'filename' , (Split-Path -Path $Path -Leaf) )
        $xmlRoot.SetAttribute( 'releaseinfo' , $xccdfXml.Benchmark.'plain-text'.InnerText )
        $xmlRoot.SetAttribute( 'title' , $xccdfXml.Benchmark.title )
        $xmlRoot.SetAttribute( 'notice' , $xccdfXml.Benchmark.notice.Id )
        $xmlRoot.SetAttribute( 'source' , $xccdfXml.Benchmark.reference.source )
        $xmlRoot.SetAttribute( 'fullversion', $stigVersionNumber )
        $xmlRoot.SetAttribute( 'created', $(Get-Date).ToShortDateString() )

        # Add the STIG types as child elements
        foreach ( $ruleType in $ruleTypeList )
        {
            # Create the rule type node
            [System.XML.XMLElement] $xmlRuleType = $xmlDocument.CreateElement( $ruleType )

            # Append as child to an existing node. DO NOT remove the [void]
            [void] $xmlRoot.appendChild( $xmlRuleType )
            $XmlRuleType.SetAttribute( $xmlattribute.ruleDscResourceModule, $dscResourceModule.$ruleType )

            # Get the rules for the current STIG type.
            $rules = $convertedStigObjects | Where-Object { $PSItem.GetType().ToString() -eq $ruleType }

            # Get the list of properties of the current object type to use as child elements
            [System.Collections.ArrayList] $properties = $rules |
                Get-Member |
                Where-Object MemberType -eq Property |
                Select-Object Name -ExpandProperty Name

            <#
                The $properties array is used to set the child elements of the rule. Remove the base
                class properties from the array list that we do not want added as child elements.
            #>
            $propertiesToRemove = @($xmlattribute.ruleId, $xmlattribute.ruleSeverity,
                $xmlattribute.ruleConversionStatus, $xmlattribute.ruleTitle,
                $xmlattribute.ruleDscResource)

            <#
                Because the Remove method on an array is case sensitive and the properties names
                in $propertiesToRemove are in different case from $properties we use the -in comparison
                operator to filter and return the proper case
            #>
            $propertiesToRemove = $properties | Where-Object -FilterScript {$PSItem -in $propertiesToRemove}

            ### [TODO] ###
            <#
                Remove the Description if explicited requested. Once all PowerSTIG
                data files are updated with the description attribute, this and
                the $DoNotExportDescription can be removed from the function. This
                field is used to automatically generate a populated STIG checklist.
            #>
            if ( $DoNotExportDescription )
            {
                $propertiesToRemove += 'Description'
            }
            ### END TODO ###

            # Remove the raw string from the output if it was not requested.
            if ( $DoNotExportRawString )
            {
                $propertiesToRemove += 'RawString'
            }

            # These properties are removed becasue they are attributes of the object, not elements
            foreach ( $propertyToRemove in $propertiesToRemove )
            {
                [void] $properties.Remove( $propertyToRemove )
            }

            # Add the STIG details to the xml document.
            foreach ( $rule in $rules )
            {
                [System.XML.XMLElement] $xmlRuleTypeProperty = $xmlDocument.CreateElement( 'Rule' )
                # Append as child to an existing node. DO NOT remove the [void]
                [void] $xmlRuleType.appendChild( $xmlRuleTypeProperty )
                # Set the base class properties
                $xmlRuleTypeProperty.SetAttribute( $xmlattribute.ruleId, $rule.ID )
                $xmlRuleTypeProperty.SetAttribute( $xmlattribute.ruleSeverity, $rule.severity )
                $xmlRuleTypeProperty.SetAttribute( $xmlattribute.ruleConversionStatus, $rule.conversionstatus )
                $xmlRuleTypeProperty.SetAttribute( $xmlattribute.ruleTitle, $rule.title )
                $xmlRuleTypeProperty.SetAttribute( $xmlattribute.ruleDscResource, $rule.dscresource )

                foreach ( $property in $properties )
                {
                    [System.XML.XMLElement] $xmlRuleTypePropertyUnique = $xmlDocument.CreateElement( $property )
                    # Append as child to an existing node. DO NOT remove the [void]
                    [void] $xmlRuleTypeProperty.appendChild( $xmlRuleTypePropertyUnique )

                    # Skip any blank vaules
                    if ($null -eq $rule.$property)
                    {
                        continue
                    }
                    <#
                        The Permission rule returns an ACE list that needs to be serialized on a second
                        level. This will pick that up and expand the object in the xml.
                    #>
                    if ($property -eq 'AccessControlEntry')
                    {
                        foreach ($ace in $rule.$property)
                        {
                            [System.XML.XMLElement] $aceEntry = $xmlDocument.CreateElement( 'Entry' )
                            [void] $xmlRuleTypePropertyUnique.appendChild( $aceEntry )

                            # Add the ace entry Type
                            [System.XML.XMLElement] $aceEntryType = $xmlDocument.CreateElement( 'Type' )
                            [void] $aceEntry.appendChild( $aceEntryType )
                            $aceEntryType.InnerText = $ace.Type

                            # Add the ace entry Principal
                            [System.XML.XMLElement] $aceEntryPrincipal = $xmlDocument.CreateElement( 'Principal' )
                            [void] $aceEntry.appendChild( $aceEntryPrincipal )
                            $aceEntryPrincipal.InnerText = $ace.Principal

                            # Add the ace entry Principal
                            [System.XML.XMLElement] $aceEntryForcePrincipal = $xmlDocument.CreateElement( 'ForcePrincipal' )
                            [void] $aceEntry.appendChild( $aceEntryForcePrincipal )
                            $aceEntryForcePrincipal.InnerText = $ace.ForcePrincipal

                            # Add the ace entry Inheritance flag
                            [System.XML.XMLElement] $aceEntryInheritance = $xmlDocument.CreateElement( 'Inheritance' )
                            [void] $aceEntry.appendChild( $aceEntryInheritance )
                            $aceEntryInheritance.InnerText = $ace.Inheritance

                            # Add the ace entery FileSystemRights
                            [System.XML.XMLElement] $aceEntryRights = $xmlDocument.CreateElement( 'Rights' )
                            [void] $aceEntry.appendChild( $aceEntryRights )
                            $aceEntryRights.InnerText = $ace.Rights
                        }
                    }
                    elseif ($property -eq 'LogCustomFieldEntry')
                    {
                        foreach ($entry in $rule.$property)
                        {
                            [System.XML.XMLElement] $logCustomFieldEntry = $xmlDocument.CreateElement( 'Entry' )
                            [void] $xmlRuleTypePropertyUnique.appendChild( $logCustomFieldEntry )

                            [System.XML.XMLElement] $entrySourceType = $xmlDocument.CreateElement( 'SourceType' )
                            [void] $logCustomFieldEntry.appendChild( $entrySourceType )
                            $entrySourceType.InnerText = $entry.SourceType

                            [System.XML.XMLElement] $entrySourceName = $xmlDocument.CreateElement( 'SourceName' )
                            [void] $logCustomFieldEntry.appendChild( $entrySourceName )
                            $entrySourceName.InnerText = $entry.SourceName
                        }
                    }
                    else
                    {
                        $xmlRuleTypePropertyUnique.InnerText = $rule.$property
                    }
                }
            }
        }

        $fileList = Get-PowerStigFileList -StigDetails $xccdfXml -Destination $Destination -Path $Path

        try
        {
            $xmlDocument.save($fileList.Settings.FullName)
            # The save method does not add the required blank line to the file
            Write-Output -InputObject "`r`n" | Out-File -FilePath $fileList.Settings.FullName -Append -Encoding utf8 -NoNewline
            Write-Output "Converted Output: $($fileList.Settings.FullName)"
        }
        catch [System.Exception]
        {
            Write-Error -Message $error[0]
        }

        if ($CreateOrgSettingsFile)
        {
            $OrganizationalSettingsXmlFileParameters = @{
                'convertedStigObjects' = $convertedStigObjects
                'StigVersionNumber'    = $stigVersionNumber
                'Destination'          = $fileList.OrgSettings.FullName
            }
            New-OrganizationalSettingsXmlFile @OrganizationalSettingsXmlFileParameters

            Write-Output "Org Settings Output: $($fileList.OrgSettings.FullName)"
        }
    }
    end
    {
        $global:VerbosePreference = $CurrentVerbosePreference
    }
}

<#
    .SYNOPSIS
        Compares the converted xml files from ConvertFrom-StigXccdf.
    .PARAMETER OldStigPath
        The full path to the previous PowerStigXml file to convert.
    .PARAMETER NewStigPath
        The full path to the current PowerStigXml file to convert.
#>
function Compare-PowerStigXml
{
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $OldStigPath,

        [Parameter(Mandatory = $true)]
        [string]
        $NewStigPath,

        [Parameter()]
        [switch]
        $IgnoreRawString
    )
    begin
    {
        $CurrentVerbosePreference = $global:VerbosePreference

        if ($PSBoundParameters.ContainsKey('Verbose'))
        {
            $global:VerbosePreference = 'Continue'
        }
    }
    process
    {

        [xml] $OldStigContent = Get-Content -Path $OldStigPath -Encoding UTF8
        [xml] $NewStigContent = Get-Content -Path $NewStigPath -Encoding UTF8

        $rules = $OldStigContent.DISASTIG.ChildNodes.ToString() -split "\s"

        $returnCompareList = @{}
        $compareObjects = @()
        $propsToIgnore = @()
        if ($ignoreRawString)
        {
            $propsToIgnore += "rawString"
        }
        foreach ( $rule in $rules )
        {
            $OldStigXml = Select-Xml -Xml $OldStigContent -XPath "//$rule/*"
            $NewStigXml = Select-Xml -Xml $NewStigContent -XPath "//$rule/*"

            if ($OldStigXml.Count -lt 2)
            {
                $prop = (Get-Member -MemberType Properties -InputObject $OldStigXml.Node).Name
            }
            else
            {
                $prop = (Get-Member -MemberType Properties -InputObject $OldStigXml.Node[0]).Name
            }
            $OldStigXml = $OldStigXml.Node | Select-Object $prop -ExcludeProperty $propsToIgnore

            if ($NewStigXml.Count -lt 2)
            {
                $prop = (Get-Member -MemberType Properties -InputObject $NewStigXml.Node).Name
            }
            else
            {
                $prop = (Get-Member -MemberType Properties -InputObject $NewStigXml.Node[0]).Name
            }
            $NewStigXml = $NewStigXml.Node | Select-Object $prop -ExcludeProperty $propsToIgnore

            $compareObjects += Compare-Object -ReferenceObject $OldStigXml -DifferenceObject $NewStigXml -Property $prop
        }

        $compareIdList = $compareObjects.Id

        foreach ($stig in $compareObjects)
        {
            $compareIdListFilter = $compareIdList |
                Where-Object {$PSitem -eq $stig.Id}

            if ($compareIdListFilter.Count -gt "1")
            {
                $delta = "changed"
            }
            else
            {
                if ($stig.SideIndicator -eq "=>")
                {
                    $delta = "added"
                }
                elseif ($stig.SideIndicator -eq "<=")
                {
                    $delta = "deleted"
                }
            }

            if ( -not $returnCompareList.ContainsKey($stig.Id))
            {
                [void] $returnCompareList.Add($stig.Id, $delta)
            }
        }
        $returnCompareList.GetEnumerator() | Sort-Object Name
    }
    end
    {
        $global:VerbosePreference = $CurrentVerbosePreference
    }
}
#endregion

#region Private Functions
$organizationalSettingRootComment = @'

    The organizational settings file is used to define the local organizations
    preferred setting within an allowed range of the STIG.

    Each setting in this file is linked by STIG ID and the valid range is in an
    associated comment.

'@

<#
    .SYNOPSIS
        Creates the Organizational settings file that accompanies the converted STIG data.
    .PARAMETER convertedStigObjects
        The Converted Stig Objects to sort through
    .PARAMETER StigVersionNumber
        The version number of the xccdf that is being processed.
    .PARAMETER Destination
        The path to store the output file.
#>
function New-OrganizationalSettingsXmlFile
{
    [CmdletBinding()]
    [OutputType()]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $ConvertedStigObjects,

        [Parameter(Mandatory = $true)]
        [version]
        $StigVersionNumber,

        [Parameter(Mandatory = $true)]
        [string]
        $Destination
    )

    $OrgSettings = Get-StigObjectsWithOrgSettings -ConvertedStigObjects $ConvertedStigObjects

    $xmlDocument = [System.XML.XMLDocument]::New()

    #########################################   Root object   ##########################################

    [System.XML.XMLElement] $xmlRootElement = $xmlDocument.CreateElement('OrganizationalSettings')

    [void] $xmlDocument.appendChild($xmlRootElement)
    [void] $xmlRootElement.SetAttribute('fullversion', $StigVersionNumber)

    $rootComment = $xmlDocument.CreateComment($organizationalSettingRootComment)
    [void] $xmlDocument.InsertBefore($rootComment, $xmlRootElement)

    #########################################   Root object   ##########################################
    #########################################    ID object    ##########################################

    foreach ($orgSetting in $OrgSettings)
    {
        $orgSettingProperty = Get-OrgSettingPropertyFromStigRule -ConvertedStig $orgSetting

        [System.XML.XMLElement] $xmlSettingChildElement = $xmlDocument.CreateElement('OrganizationalSetting')

        [void] $xmlRootElement.appendChild($xmlSettingChildElement)

        $xmlSettingChildElement.SetAttribute($xmlAttribute.ruleId , $orgSetting.id)

        foreach ($property in $orgSettingProperty)
        {
            $xmlAttribute.Add($property, $property)
            $xmlSettingChildElement.SetAttribute($xmlAttribute.$property , [string]::Empty)
            $xmlAttribute.Remove($property)
        }

        $settingComment = " Ensure $(($orgSetting.OrganizationValueTestString) -f "'$($orgSetting.Id)'")"

        $rangeNameComment = $xmlDocument.CreateComment($settingComment)
        [void] $xmlRootElement.InsertBefore($rangeNameComment, $xmlSettingChildElement)
    }

    #########################################    ID object    ##########################################

    $xmlDocument.Save($Destination)
    Write-Output -InputObject "`r`n" | Out-File -FilePath $Destination -Append -Encoding utf8 -NoNewline
}

<#
    .SYNOPSIS
        Filters the list of STIG objects and returns anything that requires an organizational decision.
    .PARAMETER convertedStigObjects
        A reference to the object that contains the converted stig data.
    .NOTES
        This function should only be called from the public ConvertTo-DscStigXml function.
#>
function Get-StigObjectsWithOrgSettings
{
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $ConvertedStigObjects
    )

    $ConvertedStigObjects |
        Where-Object { $PSitem.OrganizationValueRequired -eq $true}
}

function Get-OrgSettingPropertyFromStigRule
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $ConvertedStig
    )

    $propertiesToRemove = Get-BaseRulePropertyName
    [System.Collections.ArrayList] $rulePropertyNames = (Get-Member -InputObject $ConvertedStig -MemberType Property).Name
    foreach ($property in $propertiesToRemove)
    {
        $rulePropertyNames.RemoveAt($rulePropertyNames.IndexOf($property))
    }
    foreach ($propertyName in $rulePropertyNames)
    {
        if ([string]::IsNullOrEmpty($ConvertedStig.$propertyName))
        {
            [array] $orgSettingProperties += $propertyName
        }
    }

    return $orgSettingProperties
}

<#
    .SYNOPSIS
        Creates HardCodedRule log file entry example
    .DESCRIPTION
        Queries a specific RuleType and generates an example log file entry for
        HardCodedRules in PowerSTIG.
    .PARAMETER RuleId
        The STIG RuleId that should be included with the HardCodedRule log file
        example.
    .PARAMETER RuleType
        The RuleType(s) that should be used when creating a HardCodedRule log file
        entry.
    .EXAMPLE
        Get-HardCodedRuleLogFileEntry -RuleId V-1000 -RuleType WindowsFeatureRule

        Outputs the following single HardCodedRule log entry example:
        V-1000::*::HardCodedRule(WindowsFeatureRule)@{DscResource = 'WindowsFeature'; Ensure = $null; Name = $null}
    .EXAMPLE
        Get-HardCodedRuleLogFileEntry -RuleId V-1000 -RuleType WindowsFeatureRule, FileContentRule

        Outputs the following split HardCodedRule log entry example:
        V-1000::*::HardCodedRule(WindowsFeatureRule)@{DscResource = 'WindowsFeature'; Ensure = $null; Name = $null}<splitRule>HardCodedRule(FileContentRule)@{DscResource = 'ReplaceText'; Key = $null; Value = $null}
#>
function Get-HardCodedRuleLogFileEntry
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $RuleId
    )
    DynamicParam {
        Get-DynamicParameterRuleTypeName
    }

    begin
    {
        # Bind the specified parameter values to RuleType var
        $RuleType = $PSBoundParameters['RuleType']
        $counter = 0

        # Dynamically query the base rule common properties to remove
        $commonPropertiesToRemove = Get-BaseRulePropertyName

        # Log file patterns to build log file string
        $logFileRuleId = '{0}::*::' -f $RuleId
        $logFileHardCodedRulePattern = "{0}HardCodedRule({1}){4}DscResource = '{2}'{3}{5}"
        $keyValuePairPattern = '; {0} = $null'
        $splitRulePattern = '<splitRule>'
        $open, $close = '@{', '}'
    }

    process
    {
        $returnString = foreach ($type in $RuleType)
        {
            # Create convert rule of the given type in order to obtain rule specific properties
            $ruleTypeConvert = New-Object -TypeName ("$type`Convert")
            $ruleTypeConvert.SetDscResource()
            $ruleTypeDscResource = $ruleTypeConvert.DscResource

            # Query all valid non-base rule property names
            $ruleProperties = (Get-Member -InputObject $ruleTypeConvert -MemberType Property).Name |
                Where-Object -FilterScript {$PSItem -notin $commonPropertiesToRemove}

            # Build a string for DSC Resource specific parameters, without values
            $keyValuePair = @()
            foreach ($dscKey in $ruleProperties)
            {
                $keyValuePair += $keyValuePairPattern -f $dscKey
            }
            $keyValuePair = -join $keyValuePair

            # First time through, add the rule id, second and more will add the split delimiter
            if ($counter -eq 0)
            {
                $logFileHardCodedRulePattern -f $logFileRuleId, $type, $ruleTypeDscResource, $keyValuePair, $open, $close
                $counter++
            }
            else
            {
                $logFileHardCodedRulePattern -f $splitRulePattern, $type, $ruleTypeDscResource, $keyValuePair, $open, $close
            }
        }
        return -join $returnString
    }
}

<#
    .SYNOPSIS
        Helper function to return the base rule property names.
#>
function Get-BaseRulePropertyName
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $baseRule = [Rule]::new()
    return (Get-Member -InputObject $baseRule -MemberType Property).Name
}

<#
    .SYNOPSIS
        Returns a list of all PowerSTIG RuleTypes.
        Used to dynamically provide Values to Get-HardCodedRuleLogFileEntry
        RuleType parameter.
#>
function Get-DynamicParameterRuleTypeName
{
    [CmdletBinding()]
    [OutputType([System.Management.Automation.RuntimeDefinedParameterDictionary])]
    param()

    $parameterName = 'RuleType'
    $paramAttribute = [System.Management.Automation.ParameterAttribute]::new()
    $paramAttribute.Mandatory = $true
    $paramAttribute.Position = 1
    $getChildItemParams = @{
        Path    = "$PSScriptRoot\..\.."
        File    = $true
        Exclude = 'ManualRule.psm1', 'DocumentRule.psm1'
        Filter  = '*?Rule.psm1'
        Recurse = $true
    }
    [string[]]$validRuleTypes = (Get-ChildItem @getChildItemParams).Name -replace '.psm1'
    $validateSet = [System.Management.Automation.ValidateSetAttribute]::new($validRuleTypes)
    $attribCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
    $attribCollection.Add($paramAttribute)
    $attribCollection.Add($validateSet)
    $runtimeDefinedParam = [System.Management.Automation.RuntimeDefinedParameter]::new($parameterName, [string[]], $attribCollection)
    $runtimeDefinedParamDictionary = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
    $runtimeDefinedParamDictionary.Add($parameterName, $runtimeDefinedParam)
    return $runtimeDefinedParamDictionary
}

<#
    .SYNOPSIS
        Looks up the change log for a given xccdf file and loads the changes
#>
function Get-RuleChangeLog
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    $path = $Path -replace '\.xml', '.log'

    try
    {
        $updateLog = Get-Content -Path $path -Encoding UTF8 -Raw -ErrorAction Stop
    }
    catch
    {
        Write-Warning "$path not found. Please create it if needed."
        return @{}
    }

    # regex matches is used to capture the log content directly to the changes variable
    $changeList = [regex]::Matches(
        $updateLog, '(?<id>V-\d+)(?:::)(?<oldText>.+)(?:::)(?<newText>.+)'
    )

    # The function returns a hastable
    $updateList = @{}
    foreach ($change in $changeList)
    {
        $id = $change.Groups.Item('id').value
        $oldText = $change.Groups.Item('oldText').value
        # The trim removes any potential CRLF entries that will show up in a regex escape sequence.
        # The replace replaces `r`n with an actual new line. This is useful if you need to add data on a separate line.
        $newText = $change.Groups.Item('newText').value.Trim().Replace('`r`n',[Environment]::NewLine)

        $changeObject = [pscustomobject] @{
            OldText = $oldText
            NewText = $newText
        }

        <#
           Some rule have multiple changes that need to be made, so if a rule already
           has a change, then add the next change to the value (array)
        #>
        if ($updateList.ContainsKey($id))
        {
            $null = $updateList[$id] += $changeObject
        }
        else
        {
            $null = $updateList.Add($id, @($changeObject))
        }
    }

    $updateList
}

#endregion
