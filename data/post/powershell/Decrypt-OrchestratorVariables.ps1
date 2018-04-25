
# Rindert Kramer
# Fox-IT
# Reference: 
#       https://blog.fox-it.com/

function Get-_Help {

    $helpMsg = @"

    This tool can be used to decrypt Orchestrator variables. 
    More information: https://blog.fox-it.com/

    Required parameters:
        DatabaseServer  : DatabaseServer. <localhost\SQLEXPRESS>
        database        : Name of the database. Defaults to Orchestrator
  
    Optional parameters:
        dbaUsername     : DBA Username
        dbaPassword     : DBA Password


    The tool will use integrated authentication, unless dbaUsername and dbaPassword are specified. 
    MSSQL integrated login will then be used.

    Usage: ./Decrypt-OrchestratorVariables.ps1 -databaseServer <location>`r`n   
"@

    Write-Host $helpMsg
}

function Get-CryptedContent ([string]$content) {

    [regex]$r = '^.+\/(?<value>.+)\\.+$'
    if (-not $r.IsMatch($content)) {
        return [string]::Empty
    }

    $m = $r.Match($content)
    return $m.Groups['value'].Value
}

function Decrypt-OrchestratorVariables([string]$_databaseServer, [string]$_database, [string]$_userName = [string]::Empty, [string]$_password = [string]::Empty) {       

    # Build connectionstring based on parameter input
    $connectionString = [string]::Empty
    if ([string]::IsNullOrEmpty($userName)) {
        $connectionString = "Server=$databaseServer;Database=$database;Integrated Security=True;"
    } else {
        $connectionString = "Server=$databaseServer;uid=$userName;pwd=$password;Database=$database;Integrated Security=False;"
    }

    $connection  = New-Object System.Data.SqlClient.SqlConnection
    $command     = New-Object System.Data.SqlClient.SqlCommand
    $resultTable = New-Object System.Data.DataTable
    $results = @()

    # Query to open decryption key
    $qOpenKeys = 'OPEN SYMMETRIC KEY ORCHESTRATOR_SYM_KEY DECRYPTION BY ASYMMETRIC KEY ORCHESTRATOR_ASYM_KEY;'

    try {
        $connection.ConnectionString = $connectionString
        $connection.Open()
                
        $command.Connection = $connection

        # Open decryption key for this session
        $command.CommandText = $qOpenKeys
        [void]$command.ExecuteNonQuery()

        # Query all variables
        $qVariables = "Select VARIABLES.value, objects.Name From VARIABLES INNER JOIN OBJECTS ON OBJECTS.UniqueID = VARIABLES.UniqueID;"
        $command.CommandText = $qVariables
        [void]$resultTable.Load($command.ExecuteReader())       

        # Get all encrypted content
        foreach ($result in $resultTable | where {$_.value -match '^.+\/(?<value>.+)\\.+$'}) {
            
            $tmpTable = New-Object System.Data.DataTable

            # Get crypted value
            $cryptedContent = Get-CryptedContent -content $result.value      
            
            if ($cryptedContent -eq [string]::Empty) {
                # Maybe regex is wrong or value is not encrypted?
                # TODO: display warning?
                continue
            }  

            # Decrypt ith MSSQL encryption key
            $qDecrypt = "select convert(nvarchar, decryptbykey(0x$cryptedContent));"
            $command.CommandText = $qDecrypt
            $tmpTable.Load($command.ExecuteReader())
            
            if ($tmpTable.Rows.Count -le 0) {
                # TODO: No result, display warning?
                continue
            }
            
            $decryptedResult = $tmpTable.Rows[0][0].Replace("`0",$null) # Remove nullbytes 
            $varName = $result.Name

            $results += "[*]$varName [+]$decryptedResult"
            
            if (-not $tmpTable.Disposed) { $tmpTable.Dispose() }
        }
    }

    catch {
        throw 'Unable to extract Orchestrator secrets. Check script settings.'
    }

    finally {

        # cleanup
        $connection.Dispose()
        $command.Dispose()
        $resultTable.Dispose()
    }

    $results
}

[string]$databaseServer = '__db_server__'
[string]$database = '__database__'
[string]$dbaUsername = '__dba_username__'
[string]$dbaPassword = '__dba_password__'


Decrypt-OrchestratorVariables -_databaseServer $DatabaseServer -_database $Database -_userName $dbaUsername -_password $dbaPassword

