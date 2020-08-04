# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
# Header

<#
    .SYNOPSIS
        Automatically creates a Stig Viewer checklist from the DSC results or
        compiled MOF

    .PARAMETER ReferenceConfiguration
        The MOF that was compiled with a PowerStig composite

    .PARAMETER DscResult
        The results of Test-DscConfiguration

    .PARAMETER XccdfPath
        The path to the matching xccdf file. This is currently needed since we
        do not pull add xccdf data into PowerStig

    .PARAMETER OutputPath
        The location you want the checklist saved to

    .PARAMETER ManualCheckFile
        Location of a psd1 file containing the input for Vulnerabilities unmanaged via DSC/PowerSTIG.

    .EXAMPLE
        New-StigCheckList -ReferenceConfiguration $referenceConfiguration -XccdfPath $xccdfPath -OutputPath $outputPath

    .EXAMPLE
        New-StigCheckList -ReferenceConfiguration $referenceConfiguration -ManualCheckFile "C:\Stig\ManualChecks\2012R2-MS-1.7.psd1" -XccdfPath $xccdfPath -OutputPath $outputPath
        New-StigCheckList -ReferenceConfiguration $referenceConfiguration -ManualCheckFile $manualCheckFilePath -XccdfPath $xccdfPath -OutputPath $outputPath
#>
function New-StigCheckList
{
    [CmdletBinding()]
    [OutputType([xml])]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'mof')]
        [string]
        $ReferenceConfiguration,

        [Parameter(Mandatory = $true, ParameterSetName = 'result')]
        [psobject]
        $DscResult,

        [Parameter(Mandatory = $true)]
        [string]
        $XccdfPath,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]
        $OutputPath,

        [Parameter()]
        [String]
        $ManualCheckFile
    )

    # Validate parameters before continuing
    if ($ManualCheckFile)
    {
        if (-not (Test-Path -Path $ManualCheckFile))
        {
            throw "$($ManualCheckFile) is not a valid path to a ManualCheckFile. Provide a full valid path"
        }
        [string]$manualCheckData = Get-Content $manualCheckFile
    }

    if (-not (Test-Path -Path $OutputPath.DirectoryName))
    {
        throw "$($OutputPath.DirectoryName) is not a valid directory. Please provide a valid directory."
    }

    if ($OutputPath.Extension -ne '.ckl')
    {
        throw "$($OutputPath.FullName) is not a valid checklist extension. Please provide a full valid path ending in .ckl"
    }

    # Values for some of these fields can be read from the .mof file or the DSC results file
    if ($PSCmdlet.ParameterSetName -eq 'mof')
    {
        if (-not (Test-Path -Path $ReferenceConfiguration))
        {
            throw "$($ReferenceConfiguration) is not a valid path to a configuration (.mof) file. Please provide a valid entry."
        }

        $MofString = Get-Content -Path $ReferenceConfiguration -Raw
        $TargetNode = Get-TargetNodeFromMof($MofString)

    }
    elseif ($PSCmdlet.ParameterSetName -eq 'result')
    {
        # Check the returned object
        if ($null -eq $DscResult)
        {
            throw 'Passed in $DscResult parameter is null. Please provide a valid result using Test-DscConfiguration.'
        }
        $TargetNode = $DscResult.PSComputerName
    }

    $TargetNodeType = Get-TargetNodeType($TargetNode)

    switch ($TargetNodeType)
    {
        "MACAddress"
        {
            $HostnameMACAddress = $TargetNode
            Break
        }
        "IPv4Address"
        {
            $HostnameIPAddress = $TargetNode
            Break
        }
        "IPv6Address"
        {
            $HostnameIPAddress = $TargetNode
            Break
        }
        "FQDN"
        {
            $HostnameFQDN = $TargetNode
            Break
        }
        default
        {
            $Hostname = $TargetNode
        }
    }

    $xmlWriterSettings = [System.Xml.XmlWriterSettings]::new()
    $xmlWriterSettings.Indent = $true
    $xmlWriterSettings.IndentChars = "`t"
    $xmlWriterSettings.NewLineChars = "`n"
    $writer = [System.Xml.XmlWriter]::Create($OutputPath.FullName, $xmlWriterSettings)

    $writer.WriteStartElement('CHECKLIST')

    #region ASSET

    $writer.WriteStartElement("ASSET")

    $assetElements = [ordered] @{
        'ROLE'            = 'None'
        'ASSET_TYPE'      = 'Computing'
        'HOST_NAME'       = "$Hostname"
        'HOST_IP'         = "$HostnameIPAddress"
        'HOST_MAC'        = "$HostnameMACAddress"
        'HOST_FQDN'       = "$HostnameFQDN"
        'TECH_AREA'       = ''
        'TARGET_KEY'      = '2350'
        'WEB_OR_DATABASE' = 'false'
        'WEB_DB_SITE'     = ''
        'WEB_DB_INSTANCE' = ''
    }

    foreach ($assetElement in $assetElements.GetEnumerator())
    {
        $writer.WriteStartElement($assetElement.name)
        $writer.WriteString($assetElement.value)
        $writer.WriteEndElement()
    }

    $writer.WriteEndElement(<#ASSET#>)

    #endregion ASSET

    $writer.WriteStartElement("STIGS")
    $writer.WriteStartElement("iSTIG")

    #region STIGS/iSTIG/STIG_INFO

    $writer.WriteStartElement("STIG_INFO")

    $xccdfBenchmarkContent = Get-StigXccdfBenchmarkContent -Path $xccdfPath

    $stigInfoElements = [ordered] @{
        'version'        = $xccdfBenchmarkContent.version
        'classification' = 'UNCLASSIFIED'
        'customname'     = ''
        'stigid'         = $xccdfBenchmarkContent.id
        'description'    = $xccdfBenchmarkContent.description
        'filename'       = Split-Path -Path $xccdfPath -Leaf
        'releaseinfo'    = $xccdfBenchmarkContent.'plain-text'.InnerText
        'title'          = $xccdfBenchmarkContent.title
        'uuid'           = (New-Guid).Guid
        'notice'         = $xccdfBenchmarkContent.notice.InnerText
        'source'         = $xccdfBenchmarkContent.reference.source
    }

    foreach ($StigInfoElement in $stigInfoElements.GetEnumerator())
    {
        $writer.WriteStartElement("SI_DATA")

        $writer.WriteStartElement('SID_NAME')
        $writer.WriteString($StigInfoElement.name)
        $writer.WriteEndElement(<#SID_NAME#>)

        $writer.WriteStartElement('SID_DATA')
        $writer.WriteString($StigInfoElement.value)
        $writer.WriteEndElement(<#SID_DATA#>)

        $writer.WriteEndElement(<#SI_DATA#>)
    }

    $writer.WriteEndElement(<#STIG_INFO#>)

    #endregion STIGS/iSTIG/STIG_INFO

    #region STIGS/iSTIG/VULN[]

    # Pull in the processed XML file to check for duplicate rules for each vulnerability
    [xml]$xccdfBenchmark = Get-Content -Path $xccdfPath -Encoding UTF8
    $fileList = Get-PowerStigFileList -StigDetails $xccdfBenchmark
    $processedFileName = $fileList.Settings.FullName
    [xml]$processed = Get-Content -Path $processedFileName

    $vulnerabilities = Get-VulnerabilityList -XccdfBenchmark $xccdfBenchmarkContent

    foreach ($vulnerability in $vulnerabilities)
    {
        $writer.WriteStartElement("VULN")

        foreach ($attribute in $vulnerability.GetEnumerator())
        {
            $status = $null
            $findingDetails = $null
            $comments = $null
            $manualCheck = $null

            if ($attribute.Name -eq 'Vuln_Num')
            {
                $vid = $attribute.Value
            }

            $writer.WriteStartElement("STIG_DATA")

            $writer.WriteStartElement("VULN_ATTRIBUTE")
            $writer.WriteString($attribute.Name)
            $writer.WriteEndElement(<#VULN_ATTRIBUTE#>)

            $writer.WriteStartElement("ATTRIBUTE_DATA")
            $writer.WriteString($attribute.Value)
            $writer.WriteEndElement(<#ATTRIBUTE_DATA#>)

            $writer.WriteEndElement(<#STIG_DATA#>)
        }

        $statusMap = @{
            NotReviewed   = 'Not_Reviewed'
            Open          = 'Open'
            NotAFinding   = 'NotAFinding'
            NotApplicable = 'Not_Applicable'
        }

        if ($PSCmdlet.ParameterSetName -eq 'mof')
        {
            $setting = Get-SettingsFromMof -ReferenceConfiguration $referenceConfiguration -Id $vid
            $manualCheck = $manualCheckData | Where-Object {$_.VulID -eq $VID}

            if ($setting)
            {
                $status = $statusMap['NotAFinding']
                $comments = "To be addressed by PowerStig MOF via $setting"
                $findingDetails = Get-FindingDetails -Setting $setting

            }
            elseif ($manualCheck)
            {
                $status = $statusMap["$($manualCheck.Status)"]
                $findingDetails = $manualCheck.Details
                $comments = $manualCheck.Comments
            }
            else
            {
                $status = $statusMap['NotReviewed']
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'result')
        {
            $manualCheck = $manualCheckData | Where-Object -FilterScript {$_.VulID -eq $VID}
            # If we have manual check data, we don't need to look at the configuration
            if ($manualCheck)
            {
                $status = $statusMap["$($manualCheck.Status)"]
                $findingDetails = $manualCheck.Details
                $comments = $manualCheck.Comments
            }
            else
            {
                $setting = Get-SettingsFromResult -DscResult $dscResult -Id $vid
                if ($setting)
                {
                    if ($setting.InDesiredState -eq $true)
                    {
                        $status = $statusMap['NotAFinding']
                        $comments = "Addressed by PowerStig MOF via $setting"
                        $findingDetails = Get-FindingDetails -Setting $setting
                    }
                    elseif ($setting.InDesiredState -eq $false)
                    {
                        $status = $statusMap['Open']
                        $comments = "Configuration attempted by PowerStig MOF via $setting, but not currently set."
                        $findingDetails = Get-FindingDetails -Setting $setting
                    }
                    else
                    {
                        $status = $statusMap['Open']
                    }
                }
                else
                {
                    $status = $statusMap['NotReviewed']
                }    
            }
        }

        # Test to see if this rule is managed as a duplicate
        $convertedRule = $processed.SelectSingleNode("//Rule[@id='$vid']")

        if ($convertedRule.DuplicateOf)
        {
            # How is the duplicate rule handled? If it is handled, then this duplicate is also covered
            if ($PSCmdlet.ParameterSetName -eq 'mof')
            {
                $originalSetting = Get-SettingsFromMof -ReferenceConfiguration $referenceConfiguration -Id $convertedRule.DuplicateOf

                if ($originalSetting)
                {
                    $status = $statusMap['NotAFinding']
                    $findingDetails = 'See ' + $convertedRule.DuplicateOf + ' for Finding Details.'
                    $comments = 'Managed via PowerStigDsc - this rule is a duplicate of ' + $convertedRule.DuplicateOf
                }
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'result')
            {
                $originalSetting = Get-SettingsFromResult -DscResult $dscResult -id $convertedRule.DuplicateOf

                if ($originalSetting.InDesiredState -eq 'True')
                {
                    $status = $statusMap['NotAFinding']
                    $findingDetails = 'See ' + $convertedRule.DuplicateOf + ' for Finding Details.'
                    $comments = 'Managed via PowerStigDsc - this rule is a duplicate of ' + $convertedRule.DuplicateOf
                }
                else
                {
                    $status = $statusMap['Open']
                    $findingDetails = 'See ' + $convertedRule.DuplicateOf + ' for Finding Details.'
                    $comments = 'Managed via PowerStigDsc - this rule is a duplicate of ' + $convertedRule.DuplicateOf
                }
            }
        }

        $writer.WriteStartElement("STATUS")
        $writer.WriteString($status)
        $writer.WriteEndElement(<#STATUS#>)

        $writer.WriteStartElement("FINDING_DETAILS")
        $writer.WriteString($findingDetails)
        $writer.WriteEndElement(<#FINDING_DETAILS#>)

        $writer.WriteStartElement("COMMENTS")
        $writer.WriteString($comments)
        $writer.WriteEndElement(<#COMMENTS#>)

        $writer.WriteStartElement("SEVERITY_OVERRIDE")
        $writer.WriteString('')
        $writer.WriteEndElement(<#SEVERITY_OVERRIDE#>)

        $writer.WriteStartElement("SEVERITY_JUSTIFICATION")
        $writer.WriteString('')
        $writer.WriteEndElement(<#SEVERITY_JUSTIFICATION#>)

        $writer.WriteEndElement(<#VULN#>)
    }

    #endregion STIGS/iSTIG/VULN[]

    $writer.WriteEndElement(<#iSTIG#>)
    $writer.WriteEndElement(<#STIGS#>)
    $writer.WriteEndElement(<#CHECKLIST#>)
    $writer.Flush()
    $writer.Close()

}

<#
    .SYNOPSIS
        Gets the vulnerability details from the rule description
#>
function Get-VulnerabilityList
{
    [CmdletBinding()]
    [OutputType([xml])]
    param
    (
        [Parameter()]
        [psobject]
        $XccdfBenchmark
    )

    [System.Collections.ArrayList] $vulnerabilityList = @()

    foreach ($vulnerability in $XccdfBenchmark.Group)
    {
        [xml]$vulnerabiltyDiscussionElement = "<discussionroot>$($vulnerability.Rule.description)</discussionroot>"

        [void] $vulnerabilityList.Add(
            @(
                [PSCustomObject]@{Name = 'Vuln_Num'; Value = $vulnerability.id},
                [PSCustomObject]@{Name = 'Severity'; Value = $vulnerability.Rule.severity},
                [PSCustomObject]@{Name = 'Group_Title'; Value = $vulnerability.title},
                [PSCustomObject]@{Name = 'Rule_ID'; Value = $vulnerability.Rule.id},
                [PSCustomObject]@{Name = 'Rule_Ver'; Value = $vulnerability.Rule.version},
                [PSCustomObject]@{Name = 'Rule_Title'; Value = $vulnerability.Rule.title},
                [PSCustomObject]@{Name = 'Vuln_Discuss'; Value = $vulnerabiltyDiscussionElement.discussionroot.VulnDiscussion},
                [PSCustomObject]@{Name = 'IA_Controls'; Value = $vulnerabiltyDiscussionElement.discussionroot.IAControls},
                [PSCustomObject]@{Name = 'Check_Content'; Value = $vulnerability.Rule.check.'check-content'},
                [PSCustomObject]@{Name = 'Fix_Text'; Value = $vulnerability.Rule.fixtext.InnerText},
                [PSCustomObject]@{Name = 'False_Positives'; Value = $vulnerabiltyDiscussionElement.discussionroot.FalsePositives},
                [PSCustomObject]@{Name = 'False_Negatives'; Value = $vulnerabiltyDiscussionElement.discussionroot.FalseNegatives},
                [PSCustomObject]@{Name = 'Documentable'; Value = $vulnerabiltyDiscussionElement.discussionroot.Documentable},
                [PSCustomObject]@{Name = 'Mitigations'; Value = $vulnerabiltyDiscussionElement.discussionroot.Mitigations},
                [PSCustomObject]@{Name = 'Potential_Impact'; Value = $vulnerabiltyDiscussionElement.discussionroot.PotentialImpacts},
                [PSCustomObject]@{Name = 'Third_Party_Tools'; Value = $vulnerabiltyDiscussionElement.discussionroot.ThirdPartyTools},
                [PSCustomObject]@{Name = 'Mitigation_Control'; Value = $vulnerabiltyDiscussionElement.discussionroot.MitigationControl},
                [PSCustomObject]@{Name = 'Responsibility'; Value = $vulnerabiltyDiscussionElement.discussionroot.Responsibility},
                [PSCustomObject]@{Name = 'Security_Override_Guidance'; Value = $vulnerabiltyDiscussionElement.discussionroot.SeverityOverrideGuidance},
                [PSCustomObject]@{Name = 'Check_Content_Ref'; Value = $vulnerability.Rule.check.'check-content-ref'.href},
                [PSCustomObject]@{Name = 'Weight'; Value = $vulnerability.Rule.Weight},
                [PSCustomObject]@{Name = 'Class'; Value = 'Unclass'},
                [PSCustomObject]@{Name = 'STIGRef'; Value = "$($XccdfBenchmark.title) :: $($XccdfBenchmark.'plain-text'.InnerText)"},
                [PSCustomObject]@{Name = 'TargetKey'; Value = $vulnerability.Rule.reference.identifier}

                # Some Stigs have multiple Control Correlation Identifiers (CCI)
                $(
                    # Extract only the cci entries
                    $CCIREFList = $vulnerability.Rule.ident |
                    Where-Object {$PSItem.system -eq 'http://iase.disa.mil/cci'} |
                    Select-Object 'InnerText' -ExpandProperty 'InnerText'

                    foreach ($CCIREF in $CCIREFList)
                    {
                        [PSCustomObject]@{Name = 'CCI_REF'; Value = $CCIREF}
                    }
                )
            )
        )
    }

    return $vulnerabilityList
}

<#
    .SYNOPSIS
        Converts the mof into an array of objects
#>
function Get-MofContent
{
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ReferenceConfiguration
    )

    if (-not $script:mofContent)
    {
        $script:mofContent = [Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($referenceConfiguration, 4)
    }

    return $script:mofContent
}

<#
    .SYNOPSIS
        Gets the stig details from the mof
#>
function Get-SettingsFromMof
{
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ReferenceConfiguration,

        [Parameter(Mandatory = $true)]
        [string]
        $Id
    )

    $mofContent = Get-MofContent -ReferenceConfiguration $referenceConfiguration

    $mofContentFound = $mofContent.Where({$PSItem.ResourceID -match $Id})

    return $mofContentFound
}

<#
    .SYNOPSIS
        Gets the stig details from the Test\Get-DscConfiguration output
#>
function Get-SettingsFromResult
{
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $DscResult,

        [Parameter(Mandatory = $true)]
        [string]
        $Id
    )

    if (-not $script:allResources)
    {
        $script:allResources = $dscResult.ResourcesNotInDesiredState + $dscResult.ResourcesInDesiredState
    }

    return $script:allResources.Where({$PSItem.ResourceID -match $id})
}

<#
    .SYNOPSIS
        Gets the value from a STIG setting
#>
function Get-FindingDetails
{
    [OutputType([string])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [AllowNull()]
        [psobject]
        $Setting
    )

    switch ($setting.ResourceID)
    {
        # Only add custom entries if specific output is more valuable than dumping all properties
        {$PSItem -match "^\[None\]"}
        {
            return "No DSC resource was leveraged for this rule (Resource=None)"
        }
        {$PSItem -match "^\[(x)?Registry\]"}
        {
            return "Registry Value = $($setting.ValueData)"
        }
        {$PSItem -match "^\[UserRightsAssignment\]"}
        {
            return "UserRightsAssignment Identity = $($setting.Identity)"
        }
        default
        {
            return Get-FindingDetailsString -Setting $setting
        }
    }
}

<#
    .SYNOPSIS
        Formats properties and values with standard string format.

#>
function Get-FindingDetailsString
{
    [OutputType([string])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [AllowNull()]
        [psobject]
        $Setting
    )

    foreach ($property in $setting.PSobject.properties) {
        if ($property.TypeNameOfValue -Match 'String')
        {
            $returnString += $($property.Name) + ' = '
            $returnString += $($setting.PSobject.properties[$property.Name].Value) + "`n"
        }
    }
    return $returnString
}
function Get-TargetNodeFromMof
{
    [OutputType([string])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]
        $MofString
    )

    $pattern = "((?<=@TargetNode=')(.*)(?='))"
    $TargetNodeSearch = $mofstring | Select-String -Pattern $pattern
    $TargetNode = $TargetNodeSearch.matches.value
    return $TargetNode
}
function Get-TargetNodeType
{
    [OutputType([string])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]
        $TargetNode
    )

    switch ($TargetNode)
    {
        # Do we have a MAC address?
        {
            $_ -match '(([0-9a-f]{2}:){5}[0-9a-f]{2})'
        }
        {
            return 'MACAddress'
        }

        # Do we have an IPv6 address?
        {
            $_ -match '(([0-9a-f]{0,4}:){7}[0-9a-f]{0,4})'
        }
        {
            return 'IPv4Address'
        }

        # Do we have an IPv4 address?
        {
            $_ -match '(([0-9]{1,3}\.){3}[0-9]{1,3})'
        }
        {
            return 'IPv6Address'
        }

        # Do we have a Fully-qualified Domain Name?
        {
            $_ -match '([a-zA-Z0-9-.\+]{2,256}\.[a-z]{2,256}\b)'
        }
        {
            return 'FQDN'
        }
    }

    return ''
}
