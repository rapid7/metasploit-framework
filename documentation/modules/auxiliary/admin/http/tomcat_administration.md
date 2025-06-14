## Vulnerable Application

  The administrator application was removed as of Tomcat 6.  Tomcat 5.5.36 is available from [apache](https://archive.apache.org/dist/tomcat/tomcat-5/v5.5.36/).  This does not have the `admin` app bundled though, and can be downloaded [here](https://archive.apache.org/dist/tomcat/tomcat-5/v5.5.36/bin/apache-tomcat-5.5.36-admin.zip).
  
  To utilize the `admin` application, a user must have the permission `admin` applied to their account.  The following user line will handle all necessary permissions:

  ```
  <user username="tomcat" password="tomcat" roles="admin"/>
  ```

## Verification Steps

  1. Install Tomcat 5.5 or older
  2. Install the admin app
  3. Start msfconsole
  4. Do: ```use auxiliary/admin/http/tomcat_administration```
  5. Do: ```set rhosts [ips]```
  6. Do: ```set tomcat_user [username]```
  7. Do: ```set tomcat_pass [username]```
  8. Do: ```set rport [port]```
  9. Do: ```run```
  10. Find all the Tomcat admin portals

## Options

  **rport**

  The default is set to `8180`, which is only default on FreeBSD.  All other operating systems, and the software itself, default to `8080`.

## Scenarios

  Example run against Tomcat 5.5.36 with admin module installed against Windows XP

  ```
  msf > use auxiliary/admin/http/tomcat_administration 
  msf auxiliary(tomcat_administration) > set rport 8085
  rport => 8085
  msf auxiliary(tomcat_administration) > set rhosts 192.168.2.108
  rhosts => 192.168.2.108
  msf auxiliary(tomcat_administration) > set verbose true
  verbose => true
  msf auxiliary(tomcat_administration) > set tomcat_pass tomcat
  tomcat_pass => tomcat
  msf auxiliary(tomcat_administration) > set tomcat_user tomcat
  tomcat_user => tomcat
  msf auxiliary(tomcat_administration) > run
  
  [*] http://192.168.2.108:8085/admin [Apache-Coyote/1.1] [Apache Tomcat/5.5.36] [Tomcat Server Administration] [tomcat/tomcat]
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```
