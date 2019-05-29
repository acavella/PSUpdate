#Function Get-UpdateStatus
#{
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

	.NOTES
		Author: Tony Cavella
		GitHub  : https://github.com/revokehq/PSUpdate
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc
	
    #>
    Param
    (
		[Switch]$Debug,
		[String[]]$ComputerName	
    )
	Begin {
		If($PSBoundParameters['Debug'])
		{
			$DebugPreference = "Continue"
		}

    	$User = [Security.Principal.WindowsIdentity]::GetCurrent()
		$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
	
		if(!$Role)
		{
		Write-Warning "This function must be run with Administrative privileges."	
		} 
    }
    Process {
		
		Write-Debug "Check if ComputerName is set"
		If($ComputerName -eq $null)
		{
			Write-Debug "Set ComputerName to $env:COMPUTERNAME"
			[String[]]$ComputerName = $env:COMPUTERNAME
		} 

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
		
				#If ($pscmdlet.ShouldProcess($Computer,"Get updates history")) 
				#{
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
				#} #End If $pscmdlet.ShouldProcess($Computer,"Get updates history")
				
				################################
				# End PASS 1: Get history list #
				################################
				#endregion
				
			} #End If Test-Connection -ComputerName $Computer -Quiet
		} #End Foreach $Computer in $ComputerName	
		
		Return $UpdateCollection
	}
    End {}
#}