Function Get-WUInstallerStatus
{
    <#
	.SYNOPSIS
	    Show Windows Update Installer status.

	.DESCRIPTION
	    Use Get-WUInstallerStatus to show Windows Update Installer status.

	.PARAMETER Silent
	    Get only status True/False without any more comments on screen.
		
	.EXAMPLE
		Check if Windows Update Installer is busy.
		
		PS C:\> Get-WUInstallerStatus
		Installer is ready.

	.EXAMPLE
		Check if Windows Update Installer is busy in silent mode. Return only True (isBusy) or False (isFree).
		
		PS C:\> Get-WUInstallerStatus -Silent
		False

	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc

	.LINK
        Get-WURebootStatus
	#>
	
	[CmdletBinding(
    	SupportsShouldProcess=$True,
        ConfirmImpact="Low"
    )]
    Param
	(
		[Switch]$Silent
	)
	
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
        If ($pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Check that Windows Installer is ready to install next updates")) 
		{	    
			$objInstaller=New-Object -ComObject "Microsoft.Update.Installer"
			
			Switch($objInstaller.IsBusy)
			{
				$true	{ If($Silent) {Return $true} Else {Write-Output "Installer is busy."}}
				$false	{ If($Silent) {Return $false} Else {Write-Output "Installer is ready."}}
			} #End Switch $objInstaller.IsBusy
			
		} #End If $pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Check that Windows Installer is ready to install next updates")
	} #End Process
	
	End{}	
} #In The End :)