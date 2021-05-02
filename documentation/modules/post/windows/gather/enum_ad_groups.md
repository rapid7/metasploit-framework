## Vulnerable Application

This module will enumerate AD groups on the specified domain through LDAP.

## Verification Steps

1. Start msfconsole
1. Get a shell on a Windows target which is joined to a domain
1. Do: `use post/windows/gather/enum_ad_groups`
1. Do: `set session [#]`
1. Do: `run`
1. You should get all of the groups for the AD

## Options

### ADDITIONAL_FIELDS

Fields other than name, distinguishedname, description which should be enumerated.

### DOMAIN

The domain to enumerate.

### FILTER

Custom LDAP filter to use

### MAX_SEARCH

The maximum amount of results to retrieve.  Default is `500`, `0` for all.

## Scenarios

### Windows 2012 DC (hoodiecola domain)

```
msf6 post(windows/gather/enum_ad_groups) > sessions -i 6
[*] Starting interaction with 6...

meterpreter > sysinfo
Computer        : DC1
OS              : Windows 2012 (6.2 Build 9200).
Architecture    : x64
System Language : en_US
Domain          : hoodiecola
Logged On Users : 4
Meterpreter     : x86/windows
meterpreter > background
[*] Backgrounding session 6...
msf6 post(windows/gather/enum_ad_groups) > use post/windows/gather/enum_ad_groups 
msf6 post(windows/gather/enum_ad_groups) > set session 6
session => 6
msf6 post(windows/gather/enum_ad_groups) > run

Domain Groups
=============

 name                                     distinguishedname                                                         description
 ----                                     -----------------                                                         -----------
 WinRMRemoteWMIUsers__                    CN=WinRMRemoteWMIUsers__,CN=Users,DC=hoodiecola,DC=com                    Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
 Administrators                           CN=Administrators,CN=Builtin,DC=hoodiecola,DC=com                         Administrators have complete and unrestricted access to the computer/domain
 Users                                    CN=Users,CN=Builtin,DC=hoodiecola,DC=com                                  Users are prevented from making accidental or intentional system-wide changes and can run most applications
 Guests                                   CN=Guests,CN=Builtin,DC=hoodiecola,DC=com                                 Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted
 Print Operators                          CN=Print Operators,CN=Builtin,DC=hoodiecola,DC=com                        Members can administer domain printers
 Backup Operators                         CN=Backup Operators,CN=Builtin,DC=hoodiecola,DC=com                       Backup Operators can override security restrictions for the sole purpose of backing up or restoring files
 Replicator                               CN=Replicator,CN=Builtin,DC=hoodiecola,DC=com                             Supports file replication in a domain
 Remote Desktop Users                     CN=Remote Desktop Users,CN=Builtin,DC=hoodiecola,DC=com                   Members in this group are granted the right to logon remotely
 Network Configuration Operators          CN=Network Configuration Operators,CN=Builtin,DC=hoodiecola,DC=com        Members in this group can have some administrative privileges to manage configuration of networking features
 Performance Monitor Users                CN=Performance Monitor Users,CN=Builtin,DC=hoodiecola,DC=com              Members of this group can access performance counter data locally and remotely
 Performance Log Users                    CN=Performance Log Users,CN=Builtin,DC=hoodiecola,DC=com                  Members of this group may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access to this computer
 Distributed COM Users                    CN=Distributed COM Users,CN=Builtin,DC=hoodiecola,DC=com                  Members are allowed to launch, activate and use Distributed COM objects on this machine.
 IIS_IUSRS                                CN=IIS_IUSRS,CN=Builtin,DC=hoodiecola,DC=com                              Built-in group used by Internet Information Services.
 Cryptographic Operators                  CN=Cryptographic Operators,CN=Builtin,DC=hoodiecola,DC=com                Members are authorized to perform cryptographic operations.
 Event Log Readers                        CN=Event Log Readers,CN=Builtin,DC=hoodiecola,DC=com                      Members of this group can read event logs from local machine
 Certificate Service DCOM Access          CN=Certificate Service DCOM Access,CN=Builtin,DC=hoodiecola,DC=com        Members of this group are allowed to connect to Certification Authorities in the enterprise
 RDS Remote Access Servers                CN=RDS Remote Access Servers,CN=Builtin,DC=hoodiecola,DC=com              Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. In Internet-facing deployments, these servers are typically deployed in an edge network. This group needs to be populated on servers running RD Connection Broker. RD Gateway servers and RD Web Access servers used in the deployment need to be in this group.
 RDS Endpoint Servers                     CN=RDS Endpoint Servers,CN=Builtin,DC=hoodiecola,DC=com                   Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run. This group needs to be populated on servers running RD Connection Broker. RD Session Host servers and RD Virtualization Host servers used in the deployment need to be in this group.
 RDS Management Servers                   CN=RDS Management Servers,CN=Builtin,DC=hoodiecola,DC=com                 Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. This group needs to be populated on all servers in a Remote Desktop Services deployment. The servers running the RDS Central Management service must be included in this group.
 Hyper-V Administrators                   CN=Hyper-V Administrators,CN=Builtin,DC=hoodiecola,DC=com                 Members of this group have complete and unrestricted access to all features of Hyper-V.
 Access Control Assistance Operators      CN=Access Control Assistance Operators,CN=Builtin,DC=hoodiecola,DC=com    Members of this group can remotely query authorization attributes and permissions for resources on this computer.
 Remote Management Users                  CN=Remote Management Users,CN=Builtin,DC=hoodiecola,DC=com                Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
 Domain Computers                         CN=Domain Computers,CN=Users,DC=hoodiecola,DC=com                         All workstations and servers joined to the domain
 Domain Controllers                       CN=Domain Controllers,CN=Users,DC=hoodiecola,DC=com                       All domain controllers in the domain
 Schema Admins                            CN=Schema Admins,CN=Users,DC=hoodiecola,DC=com                            Designated administrators of the schema
 Enterprise Admins                        CN=Enterprise Admins,CN=Users,DC=hoodiecola,DC=com                        Designated administrators of the enterprise
 Cert Publishers                          CN=Cert Publishers,CN=Users,DC=hoodiecola,DC=com                          Members of this group are permitted to publish certificates to the directory
 Domain Admins                            CN=Domain Admins,CN=Users,DC=hoodiecola,DC=com                            Designated administrators of the domain
 Domain Users                             CN=Domain Users,CN=Users,DC=hoodiecola,DC=com                             All domain users
 Domain Guests                            CN=Domain Guests,CN=Users,DC=hoodiecola,DC=com                            All domain guests
 Group Policy Creator Owners              CN=Group Policy Creator Owners,CN=Users,DC=hoodiecola,DC=com              Members in this group can modify group policy for the domain
 RAS and IAS Servers                      CN=RAS and IAS Servers,CN=Users,DC=hoodiecola,DC=com                      Servers in this group can access remote access properties of users
 Server Operators                         CN=Server Operators,CN=Builtin,DC=hoodiecola,DC=com                       Members can administer domain servers
 Account Operators                        CN=Account Operators,CN=Builtin,DC=hoodiecola,DC=com                      Members can administer domain user and group accounts
 Pre-Windows 2000 Compatible Access       CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=hoodiecola,DC=com     A backward compatibility group which allows read access on all users and groups in the domain
 Incoming Forest Trust Builders           CN=Incoming Forest Trust Builders,CN=Builtin,DC=hoodiecola,DC=com         Members of this group can create incoming, one-way trusts to this forest
 Windows Authorization Access Group       CN=Windows Authorization Access Group,CN=Builtin,DC=hoodiecola,DC=com     Members of this group have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects
 Terminal Server License Servers          CN=Terminal Server License Servers,CN=Builtin,DC=hoodiecola,DC=com        Members of this group can update user accounts in Active Directory with information about license issuance, for the purpose of tracking and reporting TS Per User CAL usage
 Allowed RODC Password Replication Group  CN=Allowed RODC Password Replication Group,CN=Users,DC=hoodiecola,DC=com  Members in this group can have their passwords replicated to all read-only domain controllers in the domain
 Denied RODC Password Replication Group   CN=Denied RODC Password Replication Group,CN=Users,DC=hoodiecola,DC=com   Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
 Read-only Domain Controllers             CN=Read-only Domain Controllers,CN=Users,DC=hoodiecola,DC=com             Members of this group are Read-Only Domain Controllers in the domain
 Enterprise Read-only Domain Controllers  CN=Enterprise Read-only Domain Controllers,CN=Users,DC=hoodiecola,DC=com  Members of this group are Read-Only Domain Controllers in the enterprise
 Cloneable Domain Controllers             CN=Cloneable Domain Controllers,CN=Users,DC=hoodiecola,DC=com             Members of this group that are domain controllers may be cloned.
 DnsAdmins                                CN=DnsAdmins,CN=Users,DC=hoodiecola,DC=com                                DNS Administrators Group
 DnsUpdateProxy                           CN=DnsUpdateProxy,CN=Users,DC=hoodiecola,DC=com                           DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).
 finance                                  CN=finance,CN=Users,DC=hoodiecola,DC=com                                  
 quality control                          CN=quality control,CN=Users,DC=hoodiecola,DC=com                          

[*] Post module execution completed
```
