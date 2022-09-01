# Wrapper around Write-Host, but surrounds the string with delimiters so that we can disregard spam output originating from RemoteExchange scripts
function Write-Output ( [string] $string ) {
    $string = [string]::join("<br>",($string.Split("`r`n")))
    # <output> is a placeholder delimiter, it is later replaced by the Ruby script
    Write-Host "<output>$string</output>"
}

function Export-Mailboxes ([string] $mailbox, [string] $filter, [string] $path) {
    # $path may arrive as a short path (C:\Users\ADMINI~1\...), but Exchange does not accept short paths.
    # Get-Item is used to translate the short path to a full path.
    $path_parent = Split-Path -Path $path -Parent
    $path_leaf = Split-Path -Path $path -Leaf
    $path_parent_full = (Get-Item -LiteralPath $path_parent).FullName
    $path_full = Join-Path $path_parent_full $path_leaf

    # Convert path to a UNC path
    $path_drive = (Split-Path -Path $path_full -Qualifier)[0]
    $path_rest = Split-Path -Path $path_full -NoQualifier
    $unc_path = '\\localhost\' + $path_drive + '$' + $path_rest

    Write-Output "Exporting mailbox..."

    try {
        if ($filter -eq "") {
            # Don't use a filter
            $export_req = New-MailboxExportRequest -Priority High -Mailbox $mailbox -FilePath $unc_path
        } else {
            # Use a filter
            $export_req = New-MailboxExportRequest -Priority High -ContentFilter $filter -Mailbox $mailbox -FilePath $unc_path
        }
    }
    catch {
        $EM = $_.Exception.Message
        Write-Output "Error exporting mailbox - New-MailboxExportRequest failed"
        Write-Output "Exception message: '$EM'"
        return
    }

    if ($export_req -eq $null) {
        Write-Output "Error exporting mailbox - New-MailboxExportRequest returned null"
        return
    }

    # Monitor the export job status
    While ($true) {
        $req_status = $export_req | Get-MailboxExportRequest
        
        Write-Output ". $($req_status.Status)"

        if ($req_status.Status -eq "Failed") {
            Write-Output "Error exporting mailbox - Export job failed"
            break
        }

        if ($req_status.Status -eq "Completed") {
            Write-Output "Exporting done"
            break
        }

        Start-Sleep -Seconds 1
    }

    $export_req | Remove-MailboxExportRequest -Confirm:$false
}

function List-Mailboxes {
    # Don't throw exceptions when errors are encountered
    $Global:ErrorActionPreference = "Continue"

    $servers = Get-MailboxServer
    foreach ($server in $servers) {
        Write-Output "----------"
        Write-Output "Server:"
        Write-Output "- Name: $($server.Name)"
        Write-Output "- Version: $($server.AdminDisplayVersion)"
        Write-Output "- Role: $($server.ServerRole)"
        Write-Output "-----"
        Write-Output "Mailboxes:"
        $mailboxes = Get-Mailbox -Server $server
        foreach ($mailbox in $mailboxes) {
            Write-Output "---"
            Write-Output "- Display Name: $($mailbox.DisplayName)"
            Write-Output "- Email Addresses: $($mailbox.EmailAddresses)"
            Write-Output "- Creation date: $($mailbox.WhenMailboxCreated)"
            Write-Output "- Address list membership: $($mailbox.AddressListMembership)"

            $folderstats = $mailbox | Get-MailboxFolderStatistics -IncludeOldestAndNewestItems -IncludeAnalysis
            if ($folderstats) {
                $non_empty_folders = ( $folderstats | ? {$_.ItemsInFolder -gt 0 })
                if (!($non_empty_folders)) {
                    Write-Output "- (All folders are empty)"
                } else {
                    Write-Output "- Folders:"
                    foreach ($folderstats in $non_empty_folders) {
                        $output_string = "-- Path $($folderstats.FolderPath), Items $($folderstats.ItemsInFolder), Size $($folderstats.FolderSize)"
                        if ($folderstats.NewestItemReceivedDate) {
                            $output_string += ", Newest received date $($folderstats.NewestItemReceivedDate)"
                        }
                        Write-Output "$output_string"
                    }
                }
            }
        }
    }
}

function Ensure-Role ([string] $user, [string] $role) {
    $assignments = Get-ManagementRoleAssignment -Role $role -RoleAssignee $user -Delegating $false
    if (!($assignments)) {
        Write-Output "User not assigned to role $role - Assigning now"
        New-ManagementRoleAssignment -Role $role -User $user
    }
}

function Check-Permission {
    try {
        $Current_Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $Groups = Get-ADPrincipalGroupMembership -identity $Current_Identity.User
    } 
    catch {
        $EM = $_.Exception.Message
        Write-Output "Error getting the current user's Active Directory group membership"
        Write-Output "Exception message: '$EM'"
        return $false
    }

    return [bool] ( $Groups | ? {$_.samAccountName -eq "Organization Management" })
}

function Assign-Roles {
    $Current_Username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    # Ensure the current user has the following roles, required for the New-MailboxExportRequest cmdlet
    Ensure-Role $Current_Username "Mailbox Search"
    Ensure-Role $Current_Username "Mailbox Import Export"
}

function Get-RemoteExchangePath {
    # Get the path of the RemoteExchange.ps1 script
    $Path = $env:ExchangeInstallPath
    if (!$Path -Or !(Test-Path $Path)) {
        $Path = Join-Path $env:ProgramFiles 'Microsoft\Exchange Server\V15\'
        if (!(Test-Path $Path)) {
            $Path = Join-Path $env:ProgramFiles 'Microsoft\Exchange Server\V14\'
            if (!(Test-Path $Path)) {
                return $null
            }
        }
    }

    $RemoteExchangePath = Join-Path $Path 'Bin\RemoteExchange.ps1'
    if (!(Test-Path $RemoteExchangePath)) {
        return $null
    }

    return $RemoteExchangePath
}

# Need to set this in order to catch errors raised by RemoteExchange as exceptions
$Global:ErrorActionPreference = "Stop"

$RemoteExchangePath = Get-RemoteExchangePath
if (!($RemoteExchangePath)) {
    Write-Output "Couldn't find RemoteExchange PowerShell script"
    return
}

try {
    Import-Module $RemoteExchangePath
} 
catch {
    $EM = $_.Exception.Message
    Write-Output "Error loading the RemoteExchange PowerShell script" 
    Write-Output "Exception message: '$EM'"
    return
}

try {
    Connect-ExchangeServer -auto
}
catch {
    $EM = $_.Exception.Message
    Write-Output "Error connecting to Exchange server"
    Write-Output "Exception message: '$EM'"
    return
}

try {
    # There's a bug in Exchange 2010 that requires running an Exchange cmdlet before an AD cmdlet, otherwise the script won't work.
    # For this reason, we run Get-Mailbox here and disregard its output.
    Get-Mailbox | Out-Null

    if (!(Check-Permission)) {
        Write-Output "Permission check failed, current user must be assigned to the Organization Management role group"
        return
    }

    _COMMAND_
}
catch [System.Management.Automation.CommandNotFoundException] {
    Write-Output "A CommandNotFoundException was thrown - Some Exchange Management Shell are unavailable. This is most likely due to insufficient credentials in meterpreter session"
}
catch {
    $EM = $_.Exception.Message
    Write-Output "Aborting, caught an exception"
    Write-Output "Exception message: '$EM'"
}
