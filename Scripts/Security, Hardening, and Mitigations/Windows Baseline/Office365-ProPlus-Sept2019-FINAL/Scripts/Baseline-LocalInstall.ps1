<#
.SYNOPSIS
Applies the Office 365 ProPlus security configuration baseline to local group policy.

.DESCRIPTION
Applies the Office 365 ProPlus security configuration baseline to local group policy.

Without command-line switches, this script applies the entire recommended security
configuration baseline. You can omit parts of the baseline with these switches:

 -NoRequiredMacroSigning - Doesn't install the GPO that disallows execution of unsigned macros.
                           If this switch is not specified, unsigned macros will not execute.

 -NoLegacyFileBlock      - Doesn't install the GPO that disallows the loading or saving of
                           legacy file formats, such as .doc, .dot, .xls, etc.

 -NoExcelDDEBlock        - Doesn't install the GPO that blocks Excel from performing DDE
                           lookup or launch.

REQUIREMENTS:

* PowerShell execution policy must be configured to allow script execution; for example,
  with a command such as the following:
  Set-ExecutionPolicy RemoteSigned

* LGPO.exe must be in the Tools subdirectory or somewhere in the Path. LGPO.exe is part of
  the Security Compliance Toolkit and can be downloaded from this URL:
  https://www.microsoft.com/download/details.aspx?id=55319

.PARAMETER NoRequiredMacroSigning
If this switch is specified, the script doesn't install the GPO that disallows execution of 
unsigned macros. 
If this switch is not specified, unsigned macros will not be allowed to execute.

.PARAMETER NoLegacyFileBlock
If this switch is specified, the script doesn't install the GPO that disallows the loading or 
saving of legacy file formats, such as .doc, .dot, .xls, etc.
If this switch is not specified, Office applications will neither load nor save legacy file
formats.

.PARAMETER NoExcelDDEBlock
If this switch is specified, the script doesn't install the GPO that blocks Excel from
performing DDE lookup or launch.
If this switch is not specified, Excel will be prevented from performing DDE lookups or
launches.

#>

param(
    [switch]
    $NoRequiredMacroSigning,

    [switch]
    $NoLegacyFileBlock,

    [switch]
    $NoExcelDDEBlock
)


<#
### Do not allow this script to run on a domain controller.
### Reference re detection logic: 
### https://docs.microsoft.com/en-au/windows/win32/cimwin32prov/win32-operatingsystem
#>
if ((Get-WmiObject Win32_OperatingSystem).ProductType -eq 2)
{
    $errmsg = "`r`n" +
              "###############################################################################################`r`n" +
              "###  Execution of this local-policy script is not supported on domain controllers. Exiting. ###`r`n" +
              "###############################################################################################`r`n"
    Write-Error $errmsg
    return
}

# ### EDIT THIS SECTION WHEN GPO NAMES ARE UPDATED ###
# GPO names expected in the current baseline set
$GPO_Computer            = "MSFT Office 365 ProPlus 1908 - Computer"
$GPO_ExcelDDEBlock       = "MSFT Office 365 ProPlus 1908 - Excel DDE Block - User"
$GPO_LegacyFileBlock     = "MSFT Office 365 ProPlus 1908 - Legacy File Block - User"
$GPO_RequireMacroSigning = "MSFT Office 365 ProPlus 1908 - Require Macro Signing - User"
$GPO_User                = "MSFT Office 365 ProPlus 1908 - User"

function AddToCollection([System.Collections.Hashtable]$ht, [System.String]$GpoName)
{
    $guid = $GpoMap[$GpoName]
    if ($null -eq $guid)
    {
        $Script:bMissingGPO = $true
        Write-Error "MISSING GPO: $GpoName"
    }
    else
    {
        $ht.Add($GpoName, $guid)
    }
}

# Identify all the directories/paths
$RootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
$ParentDir = [System.IO.Path]::GetDirectoryName($RootDir)
$GPOsDir = [System.IO.Path]::Combine($ParentDir, "GPOs")
$ToolsDir = [System.IO.Path]::Combine($RootDir, "Tools")
$MapToolPs1 = [System.IO.Path]::Combine($ToolsDir, "MapGuidsToGpoNames.ps1")

# Identify all the GPOs in the baseline package by name and GUID
$GpoMap = & $MapToolPs1 $GPOsDir

$bMissingGPO = $false

# Determine which GPOs to import
$GPOsToInstall = @{}
$baselineLabel = ""

# Always install the main Computer and User GPOs
AddToCollection $GPOsToInstall $GPO_Computer
AddToCollection $GPOsToInstall $GPO_User
# Install macro-signing restrictions unless otherwise indicated
if (!$NoRequiredMacroSigning)
{
    AddToCollection $GPOsToInstall $GPO_RequireMacroSigning
}
# Install legacy file-block restrictions unless otherwise indicated
if (!$NoLegacyFileBlock)
{
    AddToCollection $GPOsToInstall $GPO_LegacyFileBlock
}
# Install Excel DDE block unless otherwise indicated
if (!$NoExcelDDEBlock)
{
    AddToCollection $GPOsToInstall $GPO_ExcelDDEBlock
}

# If any named GPOs not found, stop
if ($bMissingGPO)
{
    return
}

# Verify availability of LGPO.exe; if not in path, but in Tools subdirectory, add Tools subdirectory to the path.
$origPath = ""
if ($null -eq (Get-Command LGPO.exe -ErrorAction SilentlyContinue))
{
    if (Test-Path -Path $ToolsDir\LGPO.exe)
    {
        $origPath = $env:Path
        $env:Path = "$ToolsDir;" + $origPath
        Write-Verbose $env:Path
        Write-Verbose (Get-Command LGPO.exe)
    }
    else
    {
$lgpoErr = @"

  ============================================================================================
    LGPO.exe must be in the Tools subdirectory or somewhere in the Path. LGPO.exe is part of
    the Security Compliance Toolkit and can be downloaded from this URL:
    https://www.microsoft.com/download/details.aspx?id=55319
  ============================================================================================
"@
        Write-Error $lgpoErr
        return
    }
}

################################################################################
# Preparatory...

# All log output in Unicode
$OutputEncodingPrevious = $OutputEncoding
$OutputEncoding = [System.Text.ASCIIEncoding]::Unicode

Push-Location $RootDir

# Log file full path
$logfile = [System.IO.Path]::Combine($RootDir, "BaselineInstall-" + [datetime]::Now.ToString("yyyyMMdd-HHmm-ss") + ".log")
Write-Host "Logging to $logfile ..." -ForegroundColor Cyan
$MyInvocation.MyCommand.Name + ", " + [datetime]::Now.ToString() | Out-File -LiteralPath $logfile


# Functions to simplify logging and reporting progress to the display
$dline = "=================================================================================================="
$sline = "--------------------------------------------------------------------------------------------------"
function Log([string] $line)
{
    $line | Out-File -LiteralPath $logfile -Append
}
function LogA([string[]] $lines)
{
    $lines | foreach { Log $_ }
}
function ShowProgress([string] $line)
{
    Write-Host $line -ForegroundColor Cyan
}
function ShowProgressA([string[]] $lines)
{
    $lines | foreach { ShowProgress $_ }
}
function LogAndShowProgress([string] $line)
{
    Log $line
    ShowProgress $line
}
function LogAndShowProgressA([string[]] $lines)
{
    $lines | foreach { LogAndShowProgress $_ }
}


LogAndShowProgress $sline
LogAndShowProgress $baselineLabel
LogAndShowProgress "GPOs to be installed:"
$GPOsToInstall.Keys | Sort-Object | foreach { 
    LogAndShowProgress "`t$_" 
}
LogAndShowProgress $dline
Log ""

################################################################################

# Wrapper to run LGPO.exe so that both stdout and stderr are redirected and
# PowerShell doesn't bitch about content going to stderr.
function RunLGPO([string] $lgpoParams)
{
    ShowProgress "Running LGPO.exe $lgpoParams"
    LogA (cmd.exe /c "LGPO.exe $lgpoParams 2>&1")
}

################################################################################

# Non-GPOs and preparatory...

LogAndShowProgress "Copy custom administrative templates..."
Copy-Item -Force ..\Templates\*.admx $env:windir\PolicyDefinitions
Copy-Item -Force ..\Templates\*.adml $env:windir\PolicyDefinitions\en-US
Log $dline

# Install the GPOs
$GPOsToInstall.Keys | Sort-Object | foreach {
    $gpoName = $_
    $gpoGuid = $GPOsToInstall[$gpoName]

    Log $sline
    LogAndShowProgress "Applying GPO `"$gpoName`"..." # ( $gpoGuid )..."
    Log $sline
    Log ""
    RunLGPO "/v /g  ..\GPOs\$gpoGuid"
    Log $dline
    Log ""
}

# Restore original path if modified
if ($origPath.Length -gt 0)
{
    $env:Path = $origPath
}
# Restore original output encoding
$OutputEncoding = $OutputEncodingPrevious

# Restore original directory location
Pop-Location

################################################################################
$exitMessage = @"
To test properly, create a new non-administrative user account and reboot.

Detailed logs are in this file:
$logfile

Please post feedback to the Security Baselines Tech Community:
https://aka.ms/secguidechat
"@

Write-Host $dline
Write-Host $dline
Write-Host $exitMessage
Write-Host $dline
Write-Host $dline

################################################################################
