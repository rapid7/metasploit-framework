The `java_jmx_scanner` module uses the `Msf::Exploit::Remote::Java::Rmi::Client` library to perform a handshake with a Java JMX MBean server.   JMX MBean listens in 1099 by default, and is used to manage and monitor Java applications.

The module returns whether the target is a Java JMX MBeans server and also outputs if the server requires authentication.

## Vulnerable Application

While many implementations of JMX are available, the module was successfully tested against an Apache ActiveMQ 5.13.3 server with JMX enabled.  For convenience, a docker container (`antonw/activemq-jmx`) supports JMX and can be tweaked to require authentication.

## Verification Steps

  See [PR#10401](https://github.com/rapid7/metasploit-framework/pull/10401) for general information, and [this specific comment](https://github.com/rapid7/metasploit-framework/pull/10401#issuecomment-448705897) for steps to require JMX authentication in the container.  In summary:
  
```
docker run -p 1099:1099 antonw/activemq-jmx 
docker exec -u=root -it `docker ps -q` /bin/bash

# echo -e "monitorRole QED\ncontrolRole R&D" /etc/java-7-openjdk/management/jmxremote.password
# chown activemq /etc/java-7-openjdk/management/jmxremote.password
# chmod 400 /etc/java-7-openjdk/management/jmxremote.password
# sed 's/-Dcom.sun.management.jmxremote.authenticate=false/-Dcom.sun.management.jmxremote.authenticate=true/' /opt/apache-activemq-5.13.3/bin/env

docker restart `docker ps -q`
```

## Options

  **Option name**

  Talk about what it does, and how to use it appropriately.  If the default value is likely to change, include the default value here.

## Scenarios

### ActiveMQ 5.13.3

Against the above-described Docker container, the workflow looks like:

```
msf5 auxiliary(scanner/misc/java_jmx_server) > set RHOST 127.0.0.1
msf5 auxiliary(scanner/misc/java_jmx_server) > set RPORT 1099
msf5 auxiliary(scanner/misc/java_jmx_server) > run
[*] Reloading module...

[*] 127.0.0.1:1099        - Sending RMI header...
[*] 127.0.0.1:1099        - localhost:1099 Java JMX MBean authentication required
[*] 127.0.0.1:1099        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

In addition, note that `services` within the data model has been updated:

```
msf5 auxiliary(scanner/misc/java_jmx_server) > services 
Services
========

host             port  proto  name      state  info
----             ----  -----  ----      -----  ----
127.0.0.1        1099  tcp    java-rmi  open   JMX MBean server accessible
```
