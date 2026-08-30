[CVE-2023-21554](https://nvd.nist.gov/vuln/detail/CVE-2023-21554) ("QueueJumper") is a Remote Code Execution vulnerability with a CVSS 3.1 base score of 9.8 that could allow unauthenticated attackers to execute code on an unpatched Microsoft Windows system running [Microsoft Message Queuing (MSMQ)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms711472(v=vs.85)?redirectedfrom=MSDN).

Security updates exist for Windows Server 2008 incl. R2, Windows Server 2012 incl. R2, Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10 and Windows 11. MSMQ was first introduced with Windows NT 4.0 and Windows 2000, therefore it's likely that the vulnerability also exists and remains unpatched in unsupported Microsoft Windows versions.

The module `auxiliary/scanner/msmq/cve_2023_21554_queuejumper` scans the given targets and detects whether a running instance of MSMQ is vulnerable to CVE-2032-21554. The module doesn't affect the stability of the MSMQ service, therefore it could be safely executed against the targets.

## Vulnerable Application

Microsoft Message Queuing (MSMQ) is a message queuing service that was first introduced with Windows NT 4.0 and exists in Microsoft Windows ever since. It needs to be explicitly installed, however many enterprise applications use MSMQ and also Microsoft Exchange installs MSMQ. Applications use MSMQ to send and retrieve messages from message queues.

Besides several RPC-related TCP ports, MSMQ uses TCP port 1801 to receive messages from clients or other queue managers, leveraging the protocol [MS-MQQB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/85498b96-f2c8-43b3-a108-c9d6269dc4af). By default all queues within a queue manager allow anonymous participants to send messages.

The following operating systems are known to be vulnerable:

- Windows 7
- Windows Vista
- Windows 10 1607 (up to and excluding 10.0.14393.5850)
- Windows 10 1809 (up to and excluding 10.0.17763.4252)
- Windows 10 20h2 (up to and excluding 10.0.19042.2846)
- Windows 10 21h2 (up to and excluding 10.0.19044.2846)
- Windows 10 22h2 (up to and excluding 10.0.19045.2846)
- Windows 11 21h2 (up to and excluding 10.0.22000.1817)
- Windows 11 22h2 (up to and excluding 10.0.22621.1555)
- Windows Server 2003
- Windows Server 2003 R2
- Windows Server 2008 SP2
- Windows Server 2008 R2 SP1
- Windows Server 2012
- Windows Server 2012 R2
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022

## Verification Steps

  1. Set up a Windows target (Server 2008, Server 2008 R2, Windows 10, etc.).
  2. Start msfconsole.
  3. Load the module: `use auxiliary/scanner/msmq/cve_2023_21554_queuejumper`
  4. Specify the IP address of one or more targets: `set RHOSTS 192.168.0.1-10`
  5. Optionally, change the remote port (defaults to `1801`): `set RPORT 1840`
  6. Launch the scanner: `run`

## Scenarios

#### A vulnerable version of MSMQ within Microsoft Windows
If MSMQ is installed on the target and is lacking [security updates](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21554), the module will flag the service as vulnerable:

```
[*] 192.168.0.10:1801   - MSMQ detected. Checking for CVE-2023-21554
[+] 192.168.0.10:1801   - MSMQ vulnerable to CVE-2023-21554 - QueueJumper!
[*] Auxiliary module execution completed
```

#### A patched version of MSMQ
If the target has MSMQ running and applied the [security updates](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21554), the service is flagged as not vulnerable:

```
[*] 192.168.0.10:1801   - MSMQ detected. Checking for CVE-2023-21554
[-] 192.168.0.10:1801   - No response received, MSMQ seems to be patched
[*] Auxiliary module execution completed
```

#### A service that is not MSMQ
A non-MSMQ service will be detected by the module:

```
[-] 192.168.0.10:22      - Service does not look like MSMQ
[*] Auxiliary module execution completed
```

#### A non-accessible service
A host that either does not exist or is not reachable will be highlighted in an error message:

```
[-] 192.168.0.11:1801      - Unable to connect to the service
[*] Auxiliary module execution completed
```
