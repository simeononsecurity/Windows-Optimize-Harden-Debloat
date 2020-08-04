# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

<#
    .SYNOPSIS
        Returns the benchmark element from the xccdf xml document.

    .PARAMETER Path
        The literal path to the the zip file that contain the xccdf or the specifc xccdf file.
#>
function Get-StigXccdfBenchmarkContent
{
    [CmdletBinding()]
    [OutputType([xml])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    if (-not (Test-Path -Path $path))
    {
        Throw "The file $path was not found"
    }

    if ($path -like "*.zip")
    {
        [xml] $xccdfXmlContent = Get-StigContentFromZip -Path $path
    }
    else
    {
        [xml] $xccdfXmlContent = Get-Content -Path $path -Encoding UTF8
    }

    $xccdfXmlContent.Benchmark
}

<#
    .SYNOPSIS
        Extracts the xccdf file from the zip file provided from the DISA website.

    .PARAMETER Path
        The literal path to the zip file.
#>
function Get-StigContentFromZip
{
    [CmdletBinding()]
    [OutputType([xml])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    # Create a unique path in the users temp directory to expand the files to.
    $zipDestinationPath = "$((Split-Path -Path $path -Leaf) -replace '.zip','').$((Get-Date).Ticks)"
    Expand-Archive -LiteralPath $path -DestinationPath $zipDestinationPath
    # Get the full path to the extracted xccdf file.
    $getChildItem = @{
        Path = $zipDestinationPath
        Filter = "*Manual-xccdf.xml"
        Recurse = $true
    }

    $xccdfPath = (Get-ChildItem @getChildItem).fullName
    # Get the xccdf content before removing the content from disk.
    $xccdfContent = Get-Content -Path $xccdfPath
    # Cleanup to temp folder
    Remove-Item $zipDestinationPath -Recurse -Force

    $xccdfContent
}
