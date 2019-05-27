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
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc
	
    #>
    Param
    (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Path,
		[String]$Name
    )
    Begin 
    {
    $User = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    $Test = "Test"

    Write-Host $User
    Write-Host $Role
    Write-Warning $Test
    }
    Process {}
    End {}
#}