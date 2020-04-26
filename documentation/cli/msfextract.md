msfextract
==========

    MsfExtract - a tool to extract configbytes from an android payload.
    Usage: ./msfextract < -a apk-file -o path -j path > [options]
    Example: ./msfextract -a metasploit.apk -o /root/configbytes.txt -j /root/fernflower.jar
     
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

Among the tools needed to run msfextract, you will need the `fernflower.jar` file

Follow these steps:

    git clone https://github.com/JetBrains/intellij-community
    cd intellij-community/plugins/java-decompiler/engine/
    gradle build

You will find `fernflower.jar` in `intellij-community/plugins/java-decompiler/engine/build/libs/`

---

### Side Note:
If you do not select an output option...

(ex. `./msfextract -a whatsapp_injected.apk -j /root/fernflower.jar`)

program will still run. 

However, the temporary directory where work will be done is kept and configbytes are saved inside the directory 
as configbytes.txt

---

### Example Ouput:
    [-] No output option selected, working in /tmp/d20200417-2935-1f0wm51/
    [+] Renaming apk file to zip file
    [+] Using unzip on zip file for dex file
    [+] Using d2j-dex2jar on dex file to create jar file
    [+] Using unzip on jar file for class files
    [+] Using apktool to read AndroidManifest
    [+] Package path found: com/whatsapp
    [+] Looking for Backdoored Metasploit Payload Classes
    [+] Using fernflower to change class files to java files
    [+] Class Path: /tmp/d20200417-2935-1f0wm51/classes/com/whatsapp/qxjgv
    [+] Metasploit Backdoored Payload Class found!
    [+] /tmp/d20200417-2935-1f0wm51/java/Eeoat.java
    [+] Saved as: /tmp/d20200417-2935-1f0wm51/configbytes.txt

---

### In the end
msfextract will save configbytes of an apk in a seperate file, preferably a text file
(see [Payload 
Class](https://github.com/rapid7/metasploit-payloads/blob/master/java/androidpayload/app/src/com/metasploit/stage/Payload.java#L32))

