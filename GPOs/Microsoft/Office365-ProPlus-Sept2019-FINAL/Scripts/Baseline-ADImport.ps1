<#
.SYNOPSIS
Import all GPOs in this baseline package (in \GPOs subdirectory) into Active Directory Group Policy

#>

# Identify all the directories/paths
$RootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
$ParentDir = [System.IO.Path]::GetDirectoryName($RootDir)
$GPOsDir = [System.IO.Path]::Combine($ParentDir, "GPOs")
$ToolsDir = [System.IO.Path]::Combine($RootDir, "Tools")
$MapToolPs1 = [System.IO.Path]::Combine($ToolsDir, "MapGuidsToGpoNames.ps1")

# Identify all the GPOs in the baseline package by name and GUID
$GpoMap = & $MapToolPs1 $GPOsDir

Write-Host "Importing the following GPOs:" -ForegroundColor Cyan
Write-Host
$GpoMap.Keys | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
Write-Host
Write-Host

$GpoMap.Keys | ForEach-Object {
    $key = $_
    $guid = $GpoMap[$key]
    Write-Host ($guid + ": " + $key) -ForegroundColor Cyan
    Import-GPO -BackupId $guid -Path $GPOsDir -TargetName "$key" -CreateIfNeeded 
}
