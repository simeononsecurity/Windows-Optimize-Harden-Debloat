<#
.SYNOPSIS
Map GUIDs in a GPO backup to GPO display names

.DESCRIPTION
A GPO backup is written to a directory named with a newly-generated GUID. The GPO's display name is embedded in a "backup.xml" file in that directory. This script maps display names to GUIDs and outputs them as a sorted list or as formatted text.

.PARAMETER rootdir
Path to the directory containing one or more GPO backups.

.PARAMETER formatOutput
If this switch is specified, this script outputs text as a formatted and auto-sized table.
If this switch is not specified, this script outputs a SortedList object that can be further manipulated.

.EXAMPLE
PS C:\> MapGuidsToGpoNames.ps1 C:\GPOs\Windows-10-1903-Security-Baseline-FINAL\GPOs -formatOutput                                
Name                                                                       Value
----                                                                       -----
MSFT Internet Explorer 11 - Computer                                       {709F36C5-8A36-4147-AD59-0E97BDC937E1}
MSFT Internet Explorer 11 - User                                           {6DCED4C2-A15B-4196-BFD6-E0B0C95DAB35}
MSFT Windows 10 1903 - BitLocker                                           {1CA47B6D-E2C9-47E6-B118-3DA81F866C9F}
MSFT Windows 10 1903 - Computer                                            {7ADC8490-6FDB-483B-8F50-0D04F96393C4}
MSFT Windows 10 1903 - User                                                {9D0259DB-2897-4B47-B9D5-546DF7D961AC}
MSFT Windows 10 1903 and Server 1903 - Defender Antivirus                  {91CFE1E8-873C-4651-9CD7-B1ED210DC15D}
MSFT Windows 10 1903 and Server 1903 - Domain Security                     {23B187AE-72AC-42D2-AB34-CA19CCCB6662}
MSFT Windows 10 1903 and Server 1903 Member Server - Credential Guard      {C8D01A97-637E-4471-87F3-D7BECA95642C}
MSFT Windows Server 1903 - Domain Controller                               {2F9F252F-8D88-4114-AF1C-99FA36B2A6F4}
MSFT Windows Server 1903 - Domain Controller Virtualization Based Security {03AE3824-FBFA-4760-BC66-B8A1E1E5F122}
MSFT Windows Server 1903 - Member Server                                   {ADD7EEAB-B8C4-457E-8424-9E7A1AB72897}

#>

param(
    [parameter(Mandatory=$true)]
    [String]
    $rootdir,

    [switch]
    $formatOutput
    )

$results = New-Object System.Collections.SortedList
Get-ChildItem -Recurse -Include backup.xml $rootdir | ForEach-Object {
    $guid = $_.Directory.Name
    $displayName = ([xml](gc $_)).GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName.InnerText
    $results.Add($displayName, $guid)
}

if ($formatOutput)
{
    $results | Format-Table -AutoSize
}
else
{
    $results
}
