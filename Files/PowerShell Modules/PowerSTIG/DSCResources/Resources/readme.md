# Filenames

The file naming convention in this directory indicates the target platform and sub-component DSC resource.
Many of the STIG's define registry settings so it will be reused the most, but all resources are set up and implemented in the same manner.

For example 'Windows.xRegistry.ps1' indicates that it contains the DSC resource to manage the registry on the Windows platform.

Any composite resource in the PowerStig module can dot-source this file without having to do any additional work.
