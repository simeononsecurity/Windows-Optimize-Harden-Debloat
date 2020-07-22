<#
.SYNOPSIS
Reverts local computer to as close to default state as possible for systems that have had Exploit Protection settings applied from previous baselines.

.DESCRIPTION
Because of reported compatibility issues with the Exploit Protection settings that we began incorporating with the Windows 10 v1709 baselines, we have elected to remove the settings from the baseline and to provide a script for removing the settings from machines that have had those settings applied.
#>

# Get location of this script
$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)

Set-ProcessMitigation -PolicyFilePath $rootDir\ConfigFiles\EP-reset.xml

