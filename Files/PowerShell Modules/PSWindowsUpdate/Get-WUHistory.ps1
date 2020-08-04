Function Get-WUHistory
{
	<#
	.SYNOPSIS
	    Get list of updates history.

	.DESCRIPTION
	    Use function Get-WUHistory to get list of installed updates on current machine. It works similar like Get-Hotfix.
	       
	.PARAMETER ComputerName	
	    Specify the name of the computer to the remote connection.
 	       
	.PARAMETER Debuger	
	    Debug mode.
		
	.EXAMPLE
		Get updates histry list for sets of remote computers.
		
		PS C:\> "G1","G2" | Get-WUHistory

		ComputerName Date                KB        Title
		------------ ----                --        -----
		G1           2011-12-15 13:26:13 KB2607047 Aktualizacja systemu Windows 7 dla komputerów z procesorami x64 (KB2607047)
		G1           2011-12-15 13:25:02 KB2553385 Aktualizacja dla programu Microsoft Office 2010 (KB2553385) wersja 64-bitowa
		G1           2011-12-15 13:24:26 KB2618451 Zbiorcza aktualizacja zabezpieczeñ funkcji Killbit formantów ActiveX w sy...
		G1           2011-12-15 13:23:57 KB890830  Narzêdzie Windows do usuwania z³oœliwego oprogramowania dla komputerów z ...
		G1           2011-12-15 13:17:20 KB2589320 Aktualizacja zabezpieczeñ dla programu Microsoft Office 2010 (KB2589320) ...
		G1           2011-12-15 13:16:30 KB2620712 Aktualizacja zabezpieczeñ systemu Windows 7 dla systemów opartych na proc...
		G1           2011-12-15 13:15:52 KB2553374 Aktualizacja zabezpieczeñ dla programu Microsoft Visio 2010 (KB2553374) w...      
		G2           2011-12-17 13:39:08 KB2563227 Aktualizacja systemu Windows 7 dla komputerów z procesorami x64 (KB2563227)
		G2           2011-12-17 13:37:51 KB2425227 Aktualizacja zabezpieczeñ systemu Windows 7 dla systemów opartych na proc...
		G2           2011-12-17 13:37:23 KB2572076 Aktualizacja zabezpieczeñ dla programu Microsoft .NET Framework 3.5.1 w s...
		G2           2011-12-17 13:36:53 KB2560656 Aktualizacja zabezpieczeñ systemu Windows 7 dla systemów opartych na proc...
		G2           2011-12-17 13:36:26 KB979482  Aktualizacja zabezpieczeñ dla systemu Windows 7 dla systemów opartych na ...
		G2           2011-12-17 13:36:05 KB2535512 Aktualizacja zabezpieczeñ systemu Windows 7 dla systemów opartych na proc...
		G2           2011-12-17 13:35:41 KB2387530 Aktualizacja dla systemu Windows 7 dla systemów opartych na procesorach x...
	
	.EXAMPLE  
		Get information about specific installed updates.
	
		PS C:\> $WUHistory = Get-WUHistory
		PS C:\> $WUHistory | Where-Object {$_.Title -match "KB2607047"} | Select-Object *


		KB                  : KB2607047
		ComputerName        : G1
		Operation           : 1
		ResultCode          : 1
		HResult             : -2145116140
		Date                : 2011-12-15 13:26:13
		UpdateIdentity      : System.__ComObject
		Title               : Aktualizacja systemu Windows 7 dla komputerów z procesorami x64 (KB2607047)
		Description         : Zainstalowanie tej aktualizacji umo¿liwia rozwi¹zanie problemów w systemie Windows. Aby uzyskaæ p
		                      e³n¹ listê problemów, które zosta³y uwzglêdnione w tej aktualizacji, nale¿y zapoznaæ siê z odpowi
		                      ednim artyku³em z bazy wiedzy Microsoft Knowledge Base w celu uzyskania dodatkowych informacji. P
		                      o zainstalowaniu tego elementu mo¿e byæ konieczne ponowne uruchomienie komputera.
		UnmappedResultCode  : 0
		ClientApplicationID : AutomaticUpdates
		ServerSelection     : 1
		ServiceID           :
		UninstallationSteps : System.__ComObject
		UninstallationNotes : Tê aktualizacjê oprogramowania mo¿na usun¹æ, wybieraj¹c opcjê Wyœwietl zainstalowane aktualizacje
		                       w aplecie Programy i funkcje w Panelu sterowania.
		SupportUrl          : http://support.microsoft.com
		Categories          : System.__ComObject

	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc

	.LINK
		Get-WUList
		
	#>
	[OutputType('PSWindowsUpdate.WUHistory')]
	[CmdletBinding(
		SupportsShouldProcess=$True,
		ConfirmImpact="Low"
	)]
	Param
	(
		#Mode options
		[Switch]$Debuger,
		[parameter(ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true)]
		[String[]]$ComputerName	
	)

	Begin
	{
		If($PSBoundParameters['Debuger'])
		{
			$DebugPreference = "Continue"
		} #End If $PSBoundParameters['Debuger'] 

		$User = [Security.Principal.WindowsIdentity]::GetCurrent()
		$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

		if(!$Role)
		{
			Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."	
		} #End If !$Role		
	}
	
	Process
	{
		#region STAGE 0
		Write-Debug "STAGE 0: Prepare environment"
		######################################
		# Start STAGE 0: Prepare environment #
		######################################
		
		Write-Debug "Check if ComputerName in set"
		If($ComputerName -eq $null)
		{
			Write-Debug "Set ComputerName to localhost"
			[String[]]$ComputerName = $env:COMPUTERNAME
		} #End If $ComputerName -eq $null

		####################################
		# End STAGE 0: Prepare environment #
		####################################
		#endregion
		
		$UpdateCollection = @()
		Foreach($Computer in $ComputerName)
		{
			If(Test-Connection -ComputerName $Computer -Quiet)
			{
				#region STAGE 1
				Write-Debug "STAGE 1: Get history list"
				###################################
				# Start STAGE 1: Get history list #
				###################################
		
				If ($pscmdlet.ShouldProcess($Computer,"Get updates history")) 
				{
					Write-Verbose "Get updates history for $Computer"
					If($Computer -eq $env:COMPUTERNAME)
					{
						Write-Debug "Create Microsoft.Update.Session object for $Computer"
						$objSession = New-Object -ComObject "Microsoft.Update.Session" #Support local instance only
					} #End If $Computer -eq $env:COMPUTERNAME
					Else
					{
						Write-Debug "Create Microsoft.Update.Session object for $Computer"
						$objSession =  [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session",$Computer))
					} #End Else $Computer -eq $env:COMPUTERNAME

					Write-Debug "Create Microsoft.Update.Session.Searcher object for $Computer"
					$objSearcher = $objSession.CreateUpdateSearcher()
					$TotalHistoryCount = $objSearcher.GetTotalHistoryCount()

					If($TotalHistoryCount -gt 0)
					{
						$objHistory = $objSearcher.QueryHistory(0, $TotalHistoryCount)
						$NumberOfUpdate = 1
						Foreach($obj in $objHistory)
						{
							Write-Progress -Activity "Get update histry for $Computer" -Status "[$NumberOfUpdate/$TotalHistoryCount] $($obj.Title)" -PercentComplete ([int]($NumberOfUpdate/$TotalHistoryCount * 100))

							Write-Debug "Get update histry: $($obj.Title)"
							Write-Debug "Convert KBArticleIDs"
							$matches = $null
							$obj.Title -match "KB(\d+)" | Out-Null
							
							If($matches -eq $null)
							{
								Add-Member -InputObject $obj -MemberType NoteProperty -Name KB -Value ""
							} #End If $matches -eq $null
							Else
							{							
								Add-Member -InputObject $obj -MemberType NoteProperty -Name KB -Value ($matches[0])
							} #End Else $matches -eq $null
							
							Add-Member -InputObject $obj -MemberType NoteProperty -Name ComputerName -Value $Computer
							
							$obj.PSTypeNames.Clear()
							$obj.PSTypeNames.Add('PSWindowsUpdate.WUHistory')
						
							$UpdateCollection += $obj
							$NumberOfUpdate++
						} #End Foreach $obj in $objHistory
						Write-Progress -Activity "Get update histry for $Computer" -Status "Completed" -Completed
					} #End If $TotalHistoryCount -gt 0
					Else
					{
						Write-Warning "Probably your history was cleared. Alternative please run 'Get-WUList -IsInstalled'"
					} #End Else $TotalHistoryCount -gt 0
				} #End If $pscmdlet.ShouldProcess($Computer,"Get updates history")
				
				################################
				# End PASS 1: Get history list #
				################################
				#endregion
				
			} #End If Test-Connection -ComputerName $Computer -Quiet
		} #End Foreach $Computer in $ComputerName	
		
		Return $UpdateCollection
	} #End Process

	End{}	
} #In The End :)