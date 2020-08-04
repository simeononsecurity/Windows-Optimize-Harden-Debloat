Function Add-WUOfflineSync
{
	<#
	.SYNOPSIS
	    Register offline scaner service.

	.DESCRIPTION
	    Use Add-WUOfflineSync to register Windows Update offline scan file. You may use old wsusscan.cab or wsusscn2.cab from Microsoft Baseline Security Analyzer (MSBA) or System Management Server Inventory Tool for Microsoft Updates (SMS ITMU).
    
	.PARAMETER Path	
		Path to Windows Update offline scan file (wsusscan.cab or wsusscn2.cab).

	.PARAMETER Name	
		Name under which it will be registered Windows Update offline service. Default name is 'Offline Sync Service'.
		
	.EXAMPLE
		Try register Offline Sync Service from file C:\wsusscan.cab at default name.
	
		PS C:\> Add-WUOfflineSync -Path C:\wsusscan.cab

		Confirm
		Are you sure you want to perform this action?
		Performing operation "Register Windows Update offline scan file: C:\wsusscan.cab" on Target "G1".
		[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y

		ServiceID                            IsManaged IsDefault Name
		---------                            --------- --------- ----
		a8f3b5e6-fb1f-4814-a047-2257d39c2460 False     False     Offline Sync Service

	.EXAMPLE
		Try register Offline Sync Service from file C:\wsusscn2.cab with own name.
		
		PS C:\> Add-WUOfflineSync -Path C:\wsusscn2.cab -Name 'Offline Sync Service2'

		Confirm
		Are you sure you want to perform this action?
		Performing operation "Register Windows Update offline scan file: C:\wsusscn2.cab" on Target "G1".
		[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y

		ServiceID                            IsManaged IsDefault Name
		---------                            --------- --------- ----
		13df3d8f-78d7-4eb8-bb9c-2a101870d350 False     False     Offline Sync Service2

	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc
	
	.LINK
		http://msdn.microsoft.com/en-us/library/aa387290(v=vs.85).aspx
		http://support.microsoft.com/kb/926464

	.LINK
        Get-WUServiceManager
        Remove-WUOfflineSync
	#>
    [OutputType('PSWindowsUpdate.WUServiceManager')]
	[CmdletBinding(
        SupportsShouldProcess=$True,
        ConfirmImpact="High"
    )]
    Param
    (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Path,
		[String]$Name
    )

	Begin
	{
		$DefaultName = "Offline Sync Service" 
		
		$User = [Security.Principal.WindowsIdentity]::GetCurrent()
		$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

		if(!$Role)
		{
			Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."	
		} #End If !$Role		
	}
	
    Process
	{
		If(-not (Test-Path $Path))
		{
			Write-Warning "Windows Update offline scan file don't exist in this path: $Path"
			Return
		} #End If -not (Test-Path $Path)
		
		If($Name -eq $null)
		{
			$Name = $DefaultName
		} #End If $Name -eq $null
		
        $objServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
        Try
        {
            If ($pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Register Windows Update offline scan file: $Path")) 
			{
				$objService = $objServiceManager.AddScanPackageService($Name,$Path,1)
				$objService.PSTypeNames.Clear()
				$objService.PSTypeNames.Add('PSWindowsUpdate.WUServiceManager')
				
			} #End If $pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Register Windows Update offline scan file: $Path"
        } #End Try
        Catch 
        {
            If($_ -match "HRESULT: 0x80070005")
            {
                Write-Warning "Your security policy don't allow a non-administator identity to perform this task"
            } #End If $_ -match "HRESULT: 0x80070005"
			Else
			{
				Write-Error $_
			} #End Else $_ -match "HRESULT: 0x80070005"
			
            Return
        } #End Catch
		
        Return $objService	
	} #End Process

	End{}
} #In The End :)
