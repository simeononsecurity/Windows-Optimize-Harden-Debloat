Function Remove-WUOfflineSync
{
    <#
	.SYNOPSIS
	    Unregister offline scaner service.

	.DESCRIPTION
	    Use Remove-WUOfflineSync to unregister Windows Update offline scan file (wsusscan.cab or wsusscn2.cab) from current machine.
                              		
	.EXAMPLE
		Check if Offline Sync Service is registered and try unregister it.
	
		PS C:\> Remove-WUOfflineSync

		Confirm
		Are you sure you want to perform this action?
		Performing operation "Unregister Windows Update offline scan file" on Target "G1".
		[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y

		ServiceID                            IsManaged IsDefault Name
		---------                            --------- --------- ----
		9482f4b4-e343-43b6-b170-9a65bc822c77 False     False     Windows Update
		7971f918-a847-4430-9279-4a52d1efe18d False     False     Microsoft Update
		3da21691-e39d-4da6-8a4b-b43877bcb1b7 True      True      Windows Server Update Service

	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc

	.LINK
        Get-WUServiceManager
        Add-WUOfflineSync
	#>

	[CmdletBinding(
    	SupportsShouldProcess=$True,
        ConfirmImpact="High"
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
	    $objServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
	    
		$State = 1
	    Foreach ($objService in $objServiceManager.Services) 
	    {
	        If($objService.Name -eq "Offline Sync Service")
	        {
	           	If ($pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Unregister Windows Update offline scan file")) 
				{
					Try
					{
						$objServiceManager.RemoveService($objService.ServiceID)
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
	            } #End If $pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Unregister Windows Update offline scan file")
				
				Get-WUServiceManager
	            $State = 0;    
				
	        } #End If $objService.Name -eq "Offline Sync Service"
	    } #End Foreach $objService in $objServiceManager.Services
	    
	    If($State)
	    {
	        Write-Warning "Offline Sync Service don't exist on current machine."
	    } #End If $State
	} #End Process
	
	End{}
} #In The End :)