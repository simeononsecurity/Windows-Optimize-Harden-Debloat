Function Invoke-WUInstall
{
	<#
	.SYNOPSIS
		Invoke Get-WUInstall remotely.

	.DESCRIPTION
		Use Invoke-WUInstall to invoke Windows Update install remotly. It Based on TaskScheduler because 
		CreateUpdateDownloader() and CreateUpdateInstaller() methods can't be called from a remote computer - E_ACCESSDENIED.
		
		Note:
		Because we do not have the ability to interact, is recommended use -AcceptAll with WUInstall filters in script block.
	
	.PARAMETER ComputerName
		Specify computer name.

	.PARAMETER TaskName
		Specify task name. Default is PSWindowsUpdate.
		
	.PARAMETER Script
		Specify PowerShell script block that you what to run. Default is {ipmo PSWindowsUpdate; Get-WUInstall -AcceptAll | Out-File C:\PSWindowsUpdate.log}
		
	.EXAMPLE
		PS C:\> $Script = {ipmo PSWindowsUpdate; Get-WUInstall -AcceptAll -AutoReboot | Out-File C:\PSWindowsUpdate.log}
		PS C:\> Invoke-WUInstall -ComputerName pc1.contoso.com -Script $Script
		...
		PS C:\> Get-Content \\pc1.contoso.com\c$\PSWindowsUpdate.log
		
	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/

	.LINK
		Get-WUInstall
	#>
	[CmdletBinding(
		SupportsShouldProcess=$True,
		ConfirmImpact="High"
	)]
	param
	(
		[Parameter(ValueFromPipeline=$True,
					ValueFromPipelineByPropertyName=$True)]
		[String[]]$ComputerName,
		[String]$TaskName = "PSWindowsUpdate",
		[ScriptBlock]$Script = {ipmo PSWindowsUpdate; Get-WUInstall -AcceptAll | Out-File C:\PSWindowsUpdate.log},
		[Switch]$OnlineUpdate
	)

	Begin
	{
		$User = [Security.Principal.WindowsIdentity]::GetCurrent()
		$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

		if(!$Role)
		{
			Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."	
		} #End If !$Role
		
		$PSWUModule = Get-Module -Name PSWindowsUpdate -ListAvailable
		
		Write-Verbose "Create schedule service object"
		$Scheduler = New-Object -ComObject Schedule.Service
			
		$Task = $Scheduler.NewTask(0)

		$RegistrationInfo = $Task.RegistrationInfo
		$RegistrationInfo.Description = $TaskName
		$RegistrationInfo.Author = $User.Name

		$Settings = $Task.Settings
		$Settings.Enabled = $True
		$Settings.StartWhenAvailable = $True
		$Settings.Hidden = $False

		$Action = $Task.Actions.Create(0)
		$Action.Path = "powershell"
		$Action.Arguments = "-Command $Script"
		
		$Task.Principal.RunLevel = 1	
	}
	
	Process
	{
		ForEach($Computer in $ComputerName)
		{
			If ($pscmdlet.ShouldProcess($Computer,"Invoke WUInstall")) 
			{
				if(Test-Connection -ComputerName $Computer -Quiet)
				{
					Write-Verbose "Check PSWindowsUpdate module on $Computer"
					Try
					{
						$ModuleTest = Invoke-Command -ComputerName $Computer -ScriptBlock {Get-Module -ListAvailable -Name PSWindowsUpdate} -ErrorAction Stop
					} #End Try
					Catch
					{
						Write-Warning "Can't access to machine $Computer. Try use: winrm qc"
						Continue
					} #End Catch
					$ModulStatus = $false
					
					if($ModuleTest -eq $null -or $ModuleTest.Version -lt $PSWUModule.Version)
					{
						if($OnlineUpdate)
						{
							Update-WUModule -ComputerName $Computer
						} #End If $OnlineUpdate
						else
						{
							Update-WUModule -ComputerName $Computer	-LocalPSWUSource (Get-Module -ListAvailable -Name PSWindowsUpdate).ModuleBase
						} #End Else $OnlineUpdate
					} #End If $ModuleTest -eq $null -or $ModuleTest.Version -lt $PSWUModule.Version
					
					#Sometimes can't connect at first time
					$Info = "Connect to scheduler and register task on $Computer"
					for ($i=1; $i -le 3; $i++)
					{
						$Info += "."
						Write-Verbose $Info
						Try
						{
							$Scheduler.Connect($Computer)
							Break
						} #End Try
						Catch
						{
							if($i -ge 3)
							{
								Write-Error "Can't connect to Schedule service on $Computer" -ErrorAction Stop
							} #End If $i -ge 3
							else
							{
								sleep -Seconds 1
							} #End Else $i -ge 3
						} #End Catch					
					} #End For $i=1; $i -le 3; $i++
					
					$RootFolder = $Scheduler.GetFolder("\")
					$SendFlag = 1
					if($Scheduler.GetRunningTasks(0) | Where-Object {$_.Name -eq $TaskName})
					{
						$CurrentTask = $RootFolder.GetTask($TaskName)
						$Title = "Task $TaskName is curretly running: $($CurrentTask.Definition.Actions | Select-Object -exp Path) $($CurrentTask.Definition.Actions | Select-Object -exp Arguments)"
						$Message = "What do you want to do?"

						$ChoiceContiniue = New-Object System.Management.Automation.Host.ChoiceDescription "&Continue Current Task"
						$ChoiceStart = New-Object System.Management.Automation.Host.ChoiceDescription "Stop and Start &New Task"
						$ChoiceStop = New-Object System.Management.Automation.Host.ChoiceDescription "&Stop Task"
						$Options = [System.Management.Automation.Host.ChoiceDescription[]]($ChoiceContiniue, $ChoiceStart, $ChoiceStop)
						$SendFlag = $host.ui.PromptForChoice($Title, $Message, $Options, 0)
					
						if($SendFlag -ge 1)
						{
							($RootFolder.GetTask($TaskName)).Stop(0)
						} #End If $SendFlag -eq 1	
						
					} #End If !($Scheduler.GetRunningTasks(0) | Where-Object {$_.Name -eq $TaskName})
						
					if($SendFlag -eq 1)
					{
						$RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
						$RootFolder.GetTask($TaskName).Run(0) | Out-Null
					} #End If $SendFlag -eq 1
					
					#$RootFolder.DeleteTask($TaskName,0)
				} #End If Test-Connection -ComputerName $Computer -Quiet
				else
				{
					Write-Warning "Machine $Computer is not responding."
				} #End Else Test-Connection -ComputerName $Computer -Quiet
			} #End If $pscmdlet.ShouldProcess($Computer,"Invoke WUInstall")
		} #End ForEach $Computer in $ComputerName
		Write-Verbose "Invoke-WUInstall complete."
	}
	
	End {}

}