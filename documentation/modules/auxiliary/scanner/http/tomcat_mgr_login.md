The auxiliary/scanner/http/tomcat_mgr_login works for Tomcat versions that uses HTTP
authentication.

Please note that for Tomcat 7 or newer, the roles required to use the manager application were
changed from the single manager role to the following four roles:

* manager-gui - Allows access to the HTML GUI and the status pages.
* manager-script - Allows access to the text interface and the status pages.
* manager-jmx - Allows access to the JMX and the status pages.
* manager-status - allows access to the status pages only.

Older versions of Tomcat came with default passwords enabled by default. For example:

**Tomcat 4**

| Username | Password | Role          |
| -------- | -------- | ------------- |
| tomcat   | tomcat   | tomcat        |
| role1    | tomcat   | role1         |
| both     | tomcat   | tomcat, role1 |

**Tomcat 5**

Same as Tomcat 4

Newer Tomcat versions have these passwords commented out.

If you are using the default Metasploit credential lists, these usernames and passwords are already
loaded.


## Vulnerable Application

To download the vulnerable application, you can find it here: https://tomcat.apache.org/whichversion.html.

## Verification Steps

1. Do: ```auxiliary/scanner/http/tomcat_mgr_login```
2. Do: ```set RHOSTS [IP]```
3. Set TARGETURI if necessary.
4. Do: ```run```
