
## Vulnerable Application

This applies to all versions of SAP software.

The SAP Management Console (SAP MC) provides a common framework for centralized system management. It allows you to monitor and perform basic administration tasks on the SAP system centrally, which simplifies system administration. (https://help.sap.com/doc/saphelp_nwpi711/7.1.1/en-US/fa/ec218eb89b4424a9a0b423b0643952/frameset.htm)

SAP exposes an API on port tcp/50013 with the SOAP Management Console. Some webmethods are authenticated with a valid login/password and others are unauthenticated and reacheable by default.

With this module you can list the config files that SAP loads when starts the SAP server. This unauthenticated information disclosure can be used in a more advanced attack to get knowledge about in which paths SAP stores the config files to, for example, retrieve sensitive data or trojanize the startup process.

## Verification Steps

  Example steps:

  1. Install the SAP application. SAP provides a docker container for development purposes: https://developers.sap.com/tutorials/hxe-ua-install-using-docker.html
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/sap/sap_mgmt_con_listconfigfiles```
  4. Set up the server IP: ```set RHOSTS 192.168.10.45```
  5. Do: ```run```
  6. You will receive the list of SAP configuration files on the server.

## Options

  **RHOSTS**: Set up which server or servers do you want to test

  **RPORT**: Port tcp/50013 set up by default

  In case of more advanced deployments you can set up the SSL parameters here:

  **SSL**: Set to ```true```


## Scenarios

### Example


  ```
msf5 > use auxiliary/scanner/sap/sap_mgmt_con_listconfigfiles
msf5 auxiliary(scanner/sap/sap_mgmt_con_listconfigfiles) > show options

Module options (auxiliary/scanner/sap/sap_mgmt_con_listconfigfiles):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target address range or CIDR identifier
   RPORT    50013            yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads
   URI      /                no        Path to the SAP Management Console 
   VHOST                     no        HTTP server virtual host

 msf5 auxiliary(scanner/sap/sap_mgmt_con_listconfigfiles) > set RHOSTS 192.168.10.45
 RHOSTS => 192.168.10.45
 msf5 auxiliary(scanner/sap/sap_mgmt_con_listconfigfiles) > run
 [...]

  ```
