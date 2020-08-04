Function Get-WUServiceManager
{
	<#
	.SYNOPSIS
	    Show Service Manager configuration.

	.DESCRIPTION
	    Use Get-WUServiceManager to get available configuration of update services.
                              		
	.EXAMPLE
		Show currently available Windows Update Services on machine.
	
		PS C:\> Get-WUServiceManager

		ServiceID                            IsManaged IsDefault Name
		---------                            --------- --------- ----
		9482f4b4-e343-43b6-b170-9a65bc822c77 False     False     Windows Update
		7971f918-a847-4430-9279-4a52d1efe18d False     False     Microsoft Update
		3da21691-e39d-4da6-8a4b-b43877bcb1b7 True      True      Windows Server Update Service
		13df3d8f-78d7-4eb8-bb9c-2a101870d350 False     False     Offline Sync Service2
		a8f3b5e6-fb1f-4814-a047-2257d39c2460 False     False     Offline Sync Service

	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc

	.LINK
        Add-WUOfflineSync
        Remove-WUOfflineSync
	#>
	[OutputType('PSWindowsUpdate.WUServiceManager')]
	[CmdletBinding(
    	SupportsShouldProcess=$True,
        ConfirmImpact="Low"
    )]
    Param()
	
	Begin
	{
		$User = [Security.Principal.WindowsIdentity]::GetCurrent()
		$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

		if(!$Role)
		{
			Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."	
		} #End If !$Role	
	}
	
	Process
	{
	    If ($pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Get Windows Update ServiceManager")) 
		{
			$objServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"

			$ServiceManagerCollection = @()
	    	Foreach ($objService in $objServiceManager.Services) 
	    	{
				$objService.PSTypeNames.Clear()
				$objService.PSTypeNames.Add('PSWindowsUpdate.WUServiceManager')
						
				$ServiceManagerCollection += $objService
	    	} #End Foreach $objService in $objServiceManager.Services
			
			Return $ServiceManagerCollection
	    } #End If $pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Get Windows Update ServiceManager")		

	} #End Process
	
	End{}
} #In The End :)