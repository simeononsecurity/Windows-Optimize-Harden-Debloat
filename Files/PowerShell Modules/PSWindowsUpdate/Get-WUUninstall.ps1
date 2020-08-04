Function Get-WUUninstall
{
    <#
	.SYNOPSIS
	    Uninstall update.

	.DESCRIPTION
	    Use Get-WUUninstall to uninstall update.
                              		
	.PARAM KBArticleID	
		Update ID that will be uninstalled.
	
	.EXAMPLE
        Try to uninstall update with specific KBArticleID = KB958830
		
		Get-WUUninstall -KBArticleID KB958830

	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc

	.LINK
        Get-WUInstall
        Get-WUList
	#>
	
	[CmdletBinding(
    	SupportsShouldProcess=$True,
        ConfirmImpact="High"
    )]
    Param
    (
        [parameter(Mandatory=$true)]
		[Alias("HotFixID")]
		[String]$KBArticleID
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
	    If ($pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Uninstall update $KBArticleID")) 
		{	    
			If($KBArticleID)
		    {
		        $KBArticleID = $KBArticleID -replace "KB", ""

		        wusa /uninstall /kb:$KBArticleID
		    } #End If $KBArticleID
		    Else
		    {
		        wmic qfe list
		    } #End Else $KBArticleID
			
		} #End If $pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Uninstall update $KBArticleID")
	} #End Process
	
	End{}	
} #In The End :)