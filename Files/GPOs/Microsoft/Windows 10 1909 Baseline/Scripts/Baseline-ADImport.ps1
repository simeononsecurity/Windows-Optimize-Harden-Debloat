#
# Import all GPOs in this baseline into Active Directory Group Policy
#

$GpoMap = .\Tools\MapGuidsToGpoNames.ps1 ..\GPOs

Write-Host "Importing the following GPOs:" -ForegroundColor Cyan
Write-Host
$GpoMap.Keys | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
Write-Host
Write-Host

$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
$parentDir = [System.IO.Path]::GetDirectoryName($rootDir)
$gpoDir = [System.IO.Path]::Combine($parentDir, "GPOs")

$GpoMap.Keys | ForEach-Object {
    $key = $_
    $guid = $GpoMap[$key]
    Write-Host ($guid + ": " + $key) -ForegroundColor Cyan
    Import-GPO -BackupId $guid -Path $gpoDir -TargetName "$key" -CreateIfNeeded 
}
