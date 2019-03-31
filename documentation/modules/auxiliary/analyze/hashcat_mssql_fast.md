## Vulnerable Application

  This module attempts to use [hashcat](https://hashcat.net/hashcat/) to decode Microsoft
  SQL based password hashes, such as:

  * `mssql` based passwords (format 131)
  * `mssql05` based passwords (format 132)
  * `mssql12` based passwords (format 1731)

  Sources of hashes can be found here:
  [source](https://hashcat.net/wiki/doku.php?id=example_hashes)

## Verification Steps

  1. Have at least one user with an `mssql`, `mssql05` or `mssql12` password in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/hashcat_mssql_fast```
  4. Do: ```run```
  5. You should hopefully crack a password.

## Options

   **CUSTOM_WORDLIST**

   The path to an optional custom wordlist.  This file is added to the new wordlist which may include the other
   `USE` items like `USE_CREDS`, and have `MUTATE` or `KORELOGIC` applied to it.

   **DeleteTempFiles**

   This option will prevent deletion of the wordlist and file containing hashes.  This may be useful for
   running the hashes through john if it wasn't cracked, or for debugging. Default is `false`.

   **ITERATION_TIMEOUT**

   The max-run-time for each iteration of cracking

   **HASHCAT_PATH**

   The absolute path to the Hashcat executable.  Default behavior is to search `path` for
   `hashcat` and `hashcat.exe`.

   **MUTATE**

   Apply common mutations to the Wordlist (SLOW).  Mutations are:

   * `'@' => 'a'`
   * `'0' => 'o'`
   * `'3' => 'e'`
   * `'$' => 's'`
   * `'7' => 't'`
   * `'1' => 'l'`
   * `'5' => 's'`

   Default is `false`.

   **POT**

   The path to a John POT file (JtR option: `--pot`) to use instead.  The `pot` file is the data file which
   records cracked password hashes.  Kali linux's default location is `/root/.john/john.pot`.
   Default is `~/.msf4/john.pot`.

   **USE_CREDS**

   Use existing credential data saved in the database.  Default is `true`.

   **USE_DB_INFO**

   Use looted database schema info to seed the wordlist.  This includes the Database Name, each Table Name,
   and each Column Name.  If the DB is MSSQL, the Instance Name is also used.  Default is `true`.

   **USE_DEFAULT_WORDLIST**

   Use the default metasploit wordlist in `metasploit-framework/data/wordlists/password.lst`.  Default is
   `true`.

   **USE_HOSTNAMES**

   Seed the wordlist with hostnames from the workspace.  Default is `true`.

   **USE_ROOT_WORDS**

   Use the Common Root Words Wordlist in `metasploit-framework/data/wordlists/common_roots.txt`.  Default
   is true.

## Scenarios

Create hashes:

```
creds add user:mssql05_toto hash:0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908 jtr:mssql05
creds add user:mssql_foo hash:0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254 jtr:mssql
creds add user:mssql12_Password1! hash:0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16 jtr:mssql12 
```

Crack them:

```
resource (hashes_hashcat.rb)> use auxiliary/analyze/hashcat_mssql_fast
resource (hashes_hashcat.rb)> run
[*] Hashes Written out to /tmp/hashes_tmp20190331-19073-dnkbx7
[*] Wordlist file written out to /tmp/jtrtmp20190331-19073-1c05xc4
[*] Cracking mssql05 hashes in normal wordlist mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mssql05 hashes in increment mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracked Passwords this run:
[+] mssql05_toto:toto
[*] Cracking mssql hashes in normal wordlist mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mssql hashes in increment mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracked Passwords this run:
[+] mssql_foo:FOO
[*] Cracking mssql12 hashes in normal wordlist mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracking mssql12 hashes in increment mode...
nvmlDeviceGetFanSpeed(): Not Supported

[*] Cracked Passwords this run:
[*] Auxiliary module execution completed
```
