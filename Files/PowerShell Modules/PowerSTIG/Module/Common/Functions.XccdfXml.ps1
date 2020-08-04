# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Main Function
<#
    .SYNOPSIS
        Splits the XCCDF of the 2016 STIG into the MS and DC files

    .DESCRIPTION
        This function is a pre processor of the raw XCCDF, and only alters the Check content strings
        so that they can be processed like the rest of the STIG settings.

    .PARAMETER Path
        The path to the xccdf file to be processed.

    .PARAMETER Destination
        The folder to output the split file contents

    .EXAMPLE
        Split-StigXccdf -Path C:\Stig\Windows\U_Windows_Server_2016_STIG_V1R2_Manual-xccdf.xml -Destination C:\Dev

    .OUTPUTS
        DC and MS STIG file that is then processed by the ConvertFrom-StigXccdf
#>
function Split-StigXccdf
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Destination
    )

    begin
    {
        $currentVerbosePreference = $global:VerbosePreference

        if ($PSBoundParameters.ContainsKey('Verbose'))
        {
            $global:VerbosePreference = 'Continue'
        }
    }
    process
    {
        # Get the raw xccdf xml to pull additional details from the root node.
        [xml] $msStig = Get-Content -Path $Path
        [xml] $dcStig = $msStig.Clone()

        # Update the benchmark ID to reflect the STIG content
        $dcStig.Benchmark.id = $msStig.Benchmark.id -replace '_STIG', '_DC_STIG'
        $msStig.Benchmark.id = $msStig.Benchmark.id -replace '_STIG', '_MS_STIG'

        # Remove DC and Core settings from the MS xml
        Write-Information -MessageData "Removing Domain Controller and Core settings from Member Server STIG"

        foreach ($group in $msStig.Benchmark.Group)
        {
            # Remove DC only settings from the MS xml
            if ($group.Rule.version -match '\w-DC-\d*')
            {
                [void] $msStig.Benchmark.RemoveChild($group)
                Write-Information -MessageData "Removing $($group.id)"
                # Continue is used to bypass server core installation check
                continue
            }

            # Remove Core only settings from MS XML
            if ($group.Rule.check.'check-content' -match "For server core installations,")
            {
                [void] $msStig.Benchmark.RemoveChild($group)
                $group.Rule.check.'check-content' = $group.Rule.check.'check-content' -replace "(?=For server core installations,)(?s)(.*$)"
                [void] $msStig.Benchmark.AppendChild($group)
            }
        }

        # Remove Core and MS only settings from the DC xml
        Write-Information -MessageData "Removing Member Server settings from Domain Controller STIG"

        foreach ($group in $dcStig.Benchmark.Group)
        {
            # Remove MS only settings from DC XML
            if ($group.Rule.version -match '\w-MS-\d*')
            {
                [void] $dcStig.Benchmark.RemoveChild($group)
                Write-Information -MessageData "Removing $($group.id)"
                # Continue is used to bypass server core installation check
                continue
            }

            # Remove Core only settings from DC XML
            if ($group.Rule.check.'check-content' -match "For server core installations,")
            {
                [void] $dcStig.Benchmark.RemoveChild($group)
                $group.Rule.check.'check-content' = $group.Rule.check.'check-content' -replace "(?=For server core installations,)(?s)(.*$)"
                [void] $dcStig.Benchmark.AppendChild($group)
            }
        }

        if ([string]::IsNullOrEmpty($Destination))
        {
            $Destination = Split-Path -Path $Path -Parent
        }
        else
        {
            $Destination = $Destination.TrimEnd("\")
        }

        $filePath = "$Destination\$(Split-Path -Path $Path -Leaf)"

        $msStig.Save(($filePath -replace '_STIG_', '_MS_STIG_'))
        $dcStig.Save(($filePath -replace '_STIG_', '_DC_STIG_'))
    }
    end
    {
        $global:VerbosePreference = $currentVerbosePreference
    }
}

#endregion
#region Private Functions

<#
    .SYNOPSIS
        Get-StigRuleList determines what type of STIG setting is being processed and sends it to a
        specalized function for additional processing.

    .DESCRIPTION
        Get-StigRuleList pre-sorts the STIG rules that is recieves and tries to determine what type
        of object it should create. For example if the check content has the string HKEY, it assumes
        that the setting is a registry object and sends the check to the registry sub functions to
        further break down the string into a registry object.

    .PARAMETER StigGroupList
        An array of the child STIG Group elements from the parent Benchmark element in the xccdf.

    .PARAMETER IncludeRawString
        A flag that returns the unaltered Check-Content with the converted object.

    .NOTES
        General notes
#>
function Get-StigRuleList
{
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [psobject]
        $StigGroupList,

        [Parameter()]
        [hashtable]
        $StigGroupListChangeLog
    )

    begin
    {
        [System.Collections.ArrayList] $global:stigSettings = @()
        [int] $stigGroupCount = @($StigGroupList).Count
        [int] $stigProcessedCounter = 1

        # Global added so that the stig rule can be referenced later.
        if (-not $exclusionRuleList)
        {
            $exclusionFile = Resolve-Path -Path $PSScriptRoot\..\Common\Data.ps1
            . $exclusionFile
        }

    }
    process
    {
        foreach ($stigRule in $StigGroupList)
        {
            # This is to address STIG Rule V-18395 that has multiple rules that are exactly the same under that rule ID.
            if ($stigRule.Rule.Count -gt 1)
            {
                [void]$stigRule.RemoveChild($stigRule.Rule[0])
            }

            Write-Verbose -Message "[$stigProcessedCounter of $stigGroupCount] $($stigRule.id)"

            foreach ($correction in $StigGroupListChangeLog[$stigRule.Id])
            {
                # If the logfile contains a single * as the OldText, treat it as replacing everything with the newText value.
                if ($correction.OldText -eq '*')
                {
                    # Resetting OldText '' to the original check-content so the processed xml includes original check-content.
                    $correction.OldText = $stigRule.rule.Check.('check-content')
                    $stigRule.rule.Check.('check-content') = $correction.newText
                }
                else
                {
                    $stigRule.rule.Check.('check-content') = $stigRule.rule.Check.('check-content').Replace($correction.oldText, $correction.newText)
                }
            }

            if ($exclusionRuleList.Contains(($stigRule.id -split '\.')[0]))
            {
                [void] $global:stigSettings.Add(([DocumentRuleConvert]::new($stigRule).AsRule()))
            }
            else
            {
                $rules = [ConvertFactory]::Rule($stigRule)

                foreach ($rule in $rules)
                {
                    <#
                        At this point the original rule could be split into multiple
                        rules and we would not be sure what original text went where.
                        So we simply unwind the changes we made earlier so that any
                        new text we added is removed by reversing the regex match.
                    #>

                    # Trim the unique char from split rules if they exist
                    foreach ($correction in $StigGroupListChangeLog[($rule.Id -split '\.')[0]])
                    {
                        if ($correction.newText -match "HardCodedRule\(\w*Rule\)")
                        {
                            $rule.RawString = $correction.oldText
                        }
                        else
                        {
                            $rule.RawString = $rule.RawString.Replace($correction.newText, $correction.oldText)
                        }
                    }

                    if ($rule.title -match 'Duplicate')
                    {
                        [void] $global:stigSettings.Add(([DocumentRuleConvert]::ConvertFrom($rule)))
                    }
                    else
                    {
                        [void] $global:stigSettings.Add($rule)
                    }
                }
            }

            $stigProcessedCounter ++
        }
    }
    end
    {
        $global:stigSettings
    }

}

<#
    .SYNOPSIS
        Creates the file name to create from the xccdf content

    .PARAMETER StigDetails
        A reference to the in memory xml document.

    .NOTES
        This function should only be called from the public ConvertTo-DscStigXml function.

#>
function Get-PowerStigFileList
{
    [CmdletBinding()]
    [OutputType([Hashtable[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [xml]
        $StigDetails,

        [Parameter()]
        [string]
        $Destination,

        [Parameter()]
        [string]
        $Path
    )

    $id = Split-BenchmarkId -Id $stigDetails.Benchmark.id -FilePath $Path

    $fileNameBase = "$($id.Technology)-$($id.TechnologyVersion)"

    # If there is a technology role add it to the output name
    if ($id.TechnologyRole)
    {
        $fileNameBase = $fileNameBase + "-$($id.TechnologyRole)"
    }

    $fileNameBase = $fileNameBase + "-$(Get-StigVersionNumber -StigDetails $StigDetails)"

    if ($Destination)
    {
        $Destination = Resolve-Path -Path $Destination
    }
    else
    {
        $Destination = "$(Split-Path -Path (Split-Path -Path $PSScriptRoot))\StigData\Processed"
    }

    Write-Verbose "[$($MyInvocation.MyCommand.Name)] Destination: $Destination"

    return @{
        Settings    = [System.IO.FileInfo]::new("$Destination\$fileNameBase.xml")
        OrgSettings = [System.IO.FileInfo]::new("$Destination\$fileNameBase.org.default.xml")
    }
}

<#
    .SYNOPSIS
        Splits the Xccdf benchmark ID into an object.

    .PARAMETER Id
        The Id field from the Xccdf benchmark.

    .PARAMETER FilePath
        Specifies the file path to the xccdf. Used to determine technology role in SQL STIGs

#>
function Split-BenchmarkId
{
    [CmdletBinding()]
    [OutputType([Hashtable[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Id,

        [Parameter()]
        [string]
        $FilePath
    )

    # Different STIG's present the Id field in a different format.
    $idVariations = @(
        '(_+)STIG',
        '(_+)Security_Technical_Implementation_Guide_NewBenchmark',
        '(_+)Security_Technical_Implementation_Guide'
    )
    $sqlServerVariations = @(
        'Microsoft_SQL_Server',
        'MS_SQL_Server'
    )
    $sqlServerInstanceVariations = @(
        'Database_Instance'
    )
    $windowsVariations = @(
        'Microsoft_Windows',
        'Windows_Server',
        'Windows'
    )
    $dnsServerVariations = @(
        'Server_Domain_Name_System',
        'Domain_Name_System'
    )
    $activeDirectoryVariations = @(
        'Active_Directory'
    )
    $OfficeVariations = @(
        'Excel',
        'Outlook',
        'PowerPoint',
        'Word',
        'System',
        'Visio'
    )

    $id = $id -replace ($idVariations -join '|'), ''

    switch ($id)
    {
        {$PSItem -match "SQL_Server"}
        {
            $sqlRole = Get-SqlTechnologyRole -Path $FilePath -Id $id
            $id -match "(?<Version>\d{4})"
            $sqlVersion = $Matches['Version']
            $returnId = 'SqlServer_{0}_{1}' -f $sqlVersion, $sqlRole
            continue
        }
        {$PSItem -match "_Firewall"}
        {
            $returnId = 'WindowsFirewall_All'
            continue
        }
        {$PSItem -match "Windows_Defender_Antivirus"}
        {
            $returnId = 'WindowsDefender_All'
            continue
        }
        {$PSItem -match "IIS_8-5_Server"}
        {
            $returnId = 'IISServer_8.5'
            continue
        }
        {$PSItem -match "IIS_8-5_Site"}
        {
            $returnId = 'IISSite_8.5'
            continue
        }
        {$PSItem -match "IIS_10-0_Site"}
        {
            $returnId = 'IISSite_10.0'
            continue
        }
        {$PSItem -match "IIS_10-0_Server"}
        {
            $returnId = 'IISServer_10.0'
            continue
        }
        {$PSItem -match "Domain_Name_System"}
        {
            # The Windows Server 2012 and 2012 R2 STIGs are combined, so return the 2012R2
            $id = $id -replace '_2012_', '_2012R2_'
            $dnsStig = $id -split '_'
            $returnId = '{0}_{1}' -f 'WindowsDnsServer', $dnsStig[2]
            continue
        }
        {$PSItem -match "Windows_10"}
        {
            $returnId = $id -Replace "Windows", 'WindowsClient'
            continue
        }
        {$PSItem -match 'JRE_8'}
        {
            $returnId = 'OracleJRE_8'
            continue
        }
        {$PSItem -match "Windows"}
        {
            # The Windows Server 2012 and 2012 R2 STIGs are combined, so return the 2012R2
            $id = $id -replace '_2012_', '_2012R2_'
            $returnId = $id -replace ($windowsVariations -join '|'), 'WindowsServer'
            continue
        }
        {$PSItem -match "Active_Directory"}
        {
            $role = ($id -split '_')[-1]
            $returnId = "ActiveDirectory_All_$role"
            continue
        }
        {$PSItem -match "IE_"}
        {
            $returnId = "InternetExplorer_11"
            continue
        }
        {$PSItem -match 'FireFox'}
        {
            $returnId = "FireFox_All"
            continue
        }
        {$PSItem -match 'Excel|Outlook|PowerPoint|Word|System|Visio'}
        {
            $officeStig = ($id -split '_')

            if ($PSItem -match 'System')
            {
                $officeStig = $officeStig[2], $officeStig[3] -join ""
                $returnId = '{0}_{1}' -f 'Office', $officeStig
            }
            else
            {
                $officeStig = $officeStig[1], $officeStig[2] -join ""
                $returnId = '{0}_{1}' -f 'Office', $officeStig
            }

            continue
        }
        {$PSItem -match 'Dot_Net'}
        {
            $returnId = 'DotNetFramework_4'
            continue
        }
        {$PSItem -match 'Adobe_Acrobat_Reader'}
        {
            $returnId = 'Adobe_AcrobatReader'
            continue
        }
        {$PSItem -match 'McAfee_VirusScan'}
        {
            $returnId = 'McAfee_8.8_VirusScan'
            continue
        }
        {$PSItem -match 'Vmware_Vsphere'}
        {
            $returnId = 'Vsphere_6.5'
            continue
        }
        default
        {
            $returnId = $id
        }
    }

    $returnId = $returnId -Split '_'

    return @{
        'Technology'        = $returnId[0]
        'TechnologyVersion' = $returnId[1]
        'TechnologyRole'    = $returnId[2]
    }
}

<#
    .SYNOPSIS
        Retrieves the SQL Server technology role from the file name of the xccdf.
#>
function Get-SqlTechnologyRole
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Id,

        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $Path
    )

    $split = $Path -split '_'
    $stigIndex = $split.IndexOf('STIG')
    $sqlRole = $split[$stigIndex -1]
    if ($sqlRole -match '\w\d{1,}\w\d{1,}')
    {
        $null = $Id -match "(?<Type>Database|Instance)"
        $sqlRole = $Matches['Type']
    }

    return $sqlRole
}

<#
    .SYNOPSIS
        Creates a version number from the xccdf benchmark element details.

    .PARAMETER stigDetails
        A reference to the in memory xml document.

    .NOTES
        This function should only be called from the public ConvertTo-DscStigXml function.

#>
function Get-StigVersionNumber
{
    [CmdletBinding()]
    [OutputType([version])]
    param
    (
        [Parameter(Mandatory = $true)]
        [xml]
        $StigDetails
    )

    # Extract the revision number from the xccdf
    $revision = ($StigDetails.Benchmark.'plain-text'.'#text' -split "(Release:)(.*?)(Benchmark)")[2].trim()
    "$($StigDetails.Benchmark.version).$revision"
}

#endregion
