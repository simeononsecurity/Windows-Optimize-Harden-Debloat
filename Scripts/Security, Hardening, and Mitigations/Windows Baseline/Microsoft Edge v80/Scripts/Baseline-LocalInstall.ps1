<#
.SYNOPSIS
Import all GPOs in this baseline package (in \GPOs subdirectory) into Local Group Policy

.DESCRIPTION
Import all GPOs in this baseline package (in \GPOs subdirectory) into Local Group Policy

REQUIREMENTS:

* PowerShell execution policy must be configured to allow script execution; for example,
  with a command such as the following:
  Set-ExecutionPolicy RemoteSigned

* LGPO.exe must be in the Tools subdirectory or somewhere in the Path. LGPO.exe is part of
  the Security Compliance Toolkit and can be downloaded from this URL:
  https://www.microsoft.com/download/details.aspx?id=55319
#>

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

# Identify all the directories/paths
$RootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
$ParentDir = [System.IO.Path]::GetDirectoryName($RootDir)
$GPOsDir = [System.IO.Path]::Combine($ParentDir, "GPOs")
$ToolsDir = [System.IO.Path]::Combine($RootDir, "Tools")
$MapToolPs1 = [System.IO.Path]::Combine($ToolsDir, "MapGuidsToGpoNames.ps1")

# Identify all the GPOs in the baseline package by name and GUID
$GPOsToInstall = & $MapToolPs1 $GPOsDir


################################################################################
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
LogAndShowProgress ""
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
