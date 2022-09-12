## Vulnerable Application

This module will query the system for services and return the display name and
configuration info for each returned service. You can also optionally
filter the results by using query strings to match on specific
credentials, paths, or start types and only return the results that match.
These query operations are cumulative and if no query strings are specified,
the module will just return all services. NOTE: If the script hangs,
Windows Defender Firewall is most likely on and you did not migrate
to a safe process (explorer.exe for example).

## Verification Steps

1. Start msfconsole
2. Get a session
3. Do: `use post/windows/gather/enum_services`
4. Do: `set SESSION <session id>`
5. Do: `run`

## Options

### CRED

String to search returned service credentials for.

### PATH

String to search returned service paths for.

### TYPE

Service startup types to display (`All`, `Auto`, `Manual`, `Disabled`) (default: `All`)

## Scenarios

### Windows Server 2008 SP1 (x64)

```
msf6 > use post/windows/gather/enum_services
msf6 post(windows/gather/enum_services) > set session 1
session => 1
msf6 post(windows/gather/enum_services) > run

[*] Listing Service Info for matching services, please wait...
[+] New service credential detected: AeLookupSvc is running as 'localSystem'
[+] New service credential detected: ALG is running as 'NT AUTHORITY\LocalService'
[+] New service credential detected: CryptSvc is running as 'NT Authority\NetworkService'
[*] Found 114 Windows services matching filters

Services
========

 Name                            Credentials                  Command   Startup
 ----                            -----------                  -------   -------
 ALG                             NT AUTHORITY\LocalService    Manual    C:\Windows\System32\alg.exe
 AeLookupSvc                     localSystem                  Auto      C:\Windows\system32\svchost.exe -k netsvcs
 AppMgmt                         LocalSystem                  Manual    C:\Windows\system32\svchost.exe -k netsvcs
 Appinfo                         LocalSystem                  Manual    C:\Windows\system32\svchost.exe -k netsvcs
 AudioEndpointBuilder            LocalSystem                  Manual    C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted
 AudioSrv                        NT AUTHORITY\LocalService    Manual    C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted
 BFE                             NT AUTHORITY\LocalService    Auto      C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork
 BITS                            LocalSystem                  Auto      C:\Windows\System32\svchost.exe -k netsvcs
 Browser                         LocalSystem                  Disabled  C:\Windows\System32\svchost.exe -k netsvcs
 COMSysApp                       LocalSystem                  Manual    C:\Windows\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}
 CertPropSvc                     LocalSystem                  Manual    C:\Windows\system32\svchost.exe -k netsvcs
 CryptSvc                        NT Authority\NetworkService  Auto      C:\Windows\system32\svchost.exe -k NetworkService
 CscService                      LocalSystem                  Disabled  C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted
 DFSR                            LocalSystem                  Auto      C:\Windows\system32\DFSRs.exe
 DNS                             LocalSystem                  Auto      C:\Windows\system32\dns.exe
 DPS                             NT AUTHORITY\LocalService    Auto      C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork
 DcomLaunch                      LocalSystem                  Auto      %SystemRoot%\system32\svchost.exe -k DcomLaunch
 Dfs                             LocalSystem                  Auto      C:\Windows\system32\dfssvc.exe
 Dhcp                            NT Authority\LocalService    Auto      C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted
 Dnscache                        NT AUTHORITY\NetworkService  Auto      C:\Windows\system32\svchost.exe -k NetworkService
 EapHost                         localSystem                  Manual    C:\Windows\System32\svchost.exe -k netsvcs
 EventLog                        NT AUTHORITY\LocalService    Auto      C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted
 EventSystem                     NT AUTHORITY\LocalService    Auto      C:\Windows\system32\svchost.exe -k LocalService
 FCRegSvc                        NT AUTHORITY\LocalService    Manual    C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted
 FDResPub                        NT AUTHORITY\LocalService    Manual    C:\Windows\system32\svchost.exe -k LocalService
 IKEEXT                          LocalSystem                  Auto      C:\Windows\system32\svchost.exe -k netsvcs
 IPBusEnum                       LocalSystem                  Disabled  C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted
 IsmServ                         LocalSystem                  Auto      C:\Windows\System32\ismserv.exe
 KeyIso                          LocalSystem                  Manual    C:\Windows\system32\lsass.exe
 KtmRm                           NT AUTHORITY\NetworkService  Auto      C:\Windows\System32\svchost.exe -k NetworkService
 LanmanServer                    LocalSystem                  Auto      C:\Windows\system32\svchost.exe -k netsvcs
 LanmanWorkstation               NT AUTHORITY\LocalService    Auto      C:\Windows\System32\svchost.exe -k LocalService
 MMCSS                           LocalSystem                  Manual    C:\Windows\system32\svchost.exe -k netsvcs
 MSDTC                           NT AUTHORITY\NetworkService  Auto      C:\Windows\System32\msdtc.exe
 MSiSCSI                         LocalSystem                  Manual    C:\Windows\system32\svchost.exe -k netsvcs
 MpsSvc                          NT Authority\LocalService    Auto      C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork
 Netlogon                        LocalSystem                  Auto      C:\Windows\system32\lsass.exe
 Netman                          LocalSystem                  Manual    C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted
 NlaSvc                          NT AUTHORITY\NetworkService  Auto      C:\Windows\System32\svchost.exe -k NetworkService
 NtFrs                           LocalSystem                  Auto      C:\Windows\system32\ntfrs.exe
 PerfHost                        NT AUTHORITY\LocalService    Manual    C:\Windows\SysWow64\perfhost.exe
 PlugPlay                        LocalSystem                  Auto      C:\Windows\system32\svchost.exe -k DcomLaunch
 PolicyAgent                     NT Authority\NetworkService  Auto      C:\Windows\system32\svchost.exe -k NetworkServiceNetworkRestricted
 ProfSvc                         LocalSystem                  Auto      C:\Windows\system32\svchost.exe -k netsvcs
 ProtectedStorage                LocalSystem                  Manual    C:\Windows\system32\lsass.exe
 RSoPProv                        LocalSystem                  Manual    C:\Windows\system32\RSoPProv.exe
 RasAuto                         localSystem                  Manual    C:\Windows\System32\svchost.exe -k netsvcs
 RasMan                          localSystem                  Manual    C:\Windows\System32\svchost.exe -k netsvcs
 RemoteAccess                    localSystem                  Disabled  C:\Windows\System32\svchost.exe -k netsvcs
 RemoteRegistry                  NT AUTHORITY\LocalService    Auto      C:\Windows\system32\svchost.exe -k regsvc
 RpcLocator                      NT AUTHORITY\NetworkService  Manual    C:\Windows\system32\locator.exe
 RpcSs                           NT AUTHORITY\NetworkService  Auto      %SystemRoot%\system32\svchost.exe -k rpcss
 SCPolicySvc                     LocalSystem                  Manual    C:\Windows\system32\svchost.exe -k netsvcs
 SCardSvr                        NT AUTHORITY\LocalService    Manual    C:\Windows\system32\svchost.exe -k LocalService
 SENS                            LocalSystem                  Auto      C:\Windows\system32\svchost.exe -k netsvcs
 SLUINotify                      NT AUTHORITY\LocalService    Manual    C:\Windows\system32\svchost.exe -k LocalService
 SNMP                            LocalSystem                  Auto      C:\Windows\System32\snmp.exe
 SNMPTRAP                        NT AUTHORITY\LocalService    Manual    C:\Windows\System32\snmptrap.exe
 SSDPSRV                         NT AUTHORITY\LocalService    Disabled  C:\Windows\system32\svchost.exe -k LocalService
 SamSs                           LocalSystem                  Auto      C:\Windows\system32\lsass.exe
 Schedule                        LocalSystem                  Auto      C:\Windows\system32\svchost.exe -k netsvcs
 SessionEnv                      localSystem                  Manual    C:\Windows\System32\svchost.exe -k netsvcs
 SharedAccess                    LocalSystem                  Disabled  C:\Windows\System32\svchost.exe -k netsvcs
 ShellHWDetection                LocalSystem                  Auto      C:\Windows\System32\svchost.exe -k netsvcs
 Spooler                         LocalSystem                  Auto      C:\Windows\System32\spoolsv.exe
 SstpSvc                         NT Authority\LocalService    Manual    C:\Windows\system32\svchost.exe -k LocalService
 SysMain                         LocalSystem                  Disabled  C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted
 TBS                             NT AUTHORITY\LocalService    Auto      C:\Windows\System32\svchost.exe -k LocalService
 THREADORDER                     NT AUTHORITY\LocalService    Manual    C:\Windows\system32\svchost.exe -k LocalService
 TapiSrv                         NT AUTHORITY\NetworkService  Manual    C:\Windows\System32\svchost.exe -k tapisrv
 TermService                     NT Authority\NetworkService  Auto      C:\Windows\System32\svchost.exe -k NetworkService
 Themes                          LocalSystem                  Disabled  C:\Windows\System32\svchost.exe -k netsvcs
 TrkWks                          LocalSystem                  Manual    C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted
 TrustedInstaller                localSystem                  Manual    C:\Windows\servicing\TrustedInstaller.exe
 UI0Detect                       LocalSystem                  Manual    C:\Windows\system32\UI0Detect.exe
 UmRdpService                    localSystem                  Manual    C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted
 UxSms                           localSystem                  Auto      C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted
 VSS                             LocalSystem                  Manual    C:\Windows\system32\vssvc.exe
 W32Time                         NT AUTHORITY\LocalService    Auto      C:\Windows\system32\svchost.exe -k LocalService
 WPDBusEnum                      LocalSystem                  Manual    C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted
 WcsPlugInService                NT AUTHORITY\LocalService    Manual    C:\Windows\system32\svchost.exe -k wcssvc
 WdiServiceHost                  NT AUTHORITY\LocalService    Manual    C:\Windows\System32\svchost.exe -k wdisvc
 WdiSystemHost                   LocalSystem                  Manual    C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted
 Wecsvc                          NT AUTHORITY\NetworkService  Manual    C:\Windows\system32\svchost.exe -k NetworkService
 WerSvc                          localSystem                  Auto      C:\Windows\System32\svchost.exe -k WerSvcGroup
 WinHttpAutoProxySvc             NT AUTHORITY\LocalService    Manual    C:\Windows\system32\svchost.exe -k LocalService
 WinRM                           NT AUTHORITY\NetworkService  Auto      C:\Windows\System32\svchost.exe -k NetworkService
 Winmgmt                         localSystem                  Auto      C:\Windows\system32\svchost.exe -k netsvcs
 clr_optimization_v2.0.50727_32  LocalSystem                  Manual    C:\Windows\Microsoft.NET\Framework\v2.0.50727\mscorsvw.exe
 clr_optimization_v2.0.50727_64  LocalSystem                  Manual    C:\Windows\Microsoft.NET\Framework64\v2.0.50727\mscorsvw.exe
 dot3svc                         localSystem                  Manual    C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted
 fdPHost                         NT AUTHORITY\LocalService    Manual    C:\Windows\system32\svchost.exe -k LocalService
 gpsvc                           LocalSystem                  Auto      C:\Windows\system32\svchost.exe -k GPSvcGroup
 hidserv                         LocalSystem                  Manual    C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted
 hkmsvc                          localSystem                  Manual    C:\Windows\System32\svchost.exe -k netsvcs
 iphlpsvc                        LocalSystem                  Auto      C:\Windows\System32\svchost.exe -k NetSvcs
 kdc                             LocalSystem                  Auto      C:\Windows\System32\lsass.exe
 lltdsvc                         NT AUTHORITY\LocalService    Manual    C:\Windows\System32\svchost.exe -k LocalService
 lmhosts                         NT AUTHORITY\LocalService    Auto      C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted
 msiserver                       LocalSystem                  Manual    C:\Windows\system32\msiexec /V
 napagent                        NT AUTHORITY\NetworkService  Manual    C:\Windows\System32\svchost.exe -k NetworkService
 netprofm                        NT AUTHORITY\LocalService    Auto      C:\Windows\System32\svchost.exe -k LocalService
 nsi                             NT Authority\LocalService    Auto      C:\Windows\system32\svchost.exe -k LocalService
 pla                             NT AUTHORITY\LocalService    Manual    %SystemRoot%\System32\svchost.exe -k LocalServiceNoNetwork
 sacsvr                          LocalSystem                  Manual    C:\Windows\System32\svchost.exe -k netsvcs
 seclogon                        LocalSystem                  Auto      C:\Windows\system32\svchost.exe -k netsvcs
 slsvc                           NT AUTHORITY\NetworkService  Auto      C:\Windows\system32\SLsvc.exe
 swprv                           LocalSystem                  Manual    C:\Windows\System32\svchost.exe -k swprv
 upnphost                        NT AUTHORITY\LocalService    Disabled  C:\Windows\system32\svchost.exe -k LocalService
 vds                             LocalSystem                  Manual    C:\Windows\System32\vds.exe
 wercplsupport                   localSystem                  Manual    C:\Windows\System32\svchost.exe -k netsvcs
 wmiApSrv                        localSystem                  Manual    C:\Windows\system32\wbem\WmiApSrv.exe
 wuauserv                        LocalSystem                  Auto      C:\Windows\system32\svchost.exe -k netsvcs
 wudfsvc                         LocalSystem                  Manual    C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted

[+] Loot file stored in: /root/.msf4/loot/20220820231513_default_192.168.200.218_windows.services_350986.txt
[*] Post module execution completed
```
