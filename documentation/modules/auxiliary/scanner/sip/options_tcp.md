## Vulnerable Application

  SIP is a signaling protocol for voice, and video typically associated with VOIP and typically used in commercial
  phone systems.  SIP and VOIP are gaining popularity with home and cellular voice/video calling systems as well.

  This module scans the TCP port to identify what OPTIONS are available on the SIP service.

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/scanner/sip/options_tcp```
  3. Do: ```set rhosts [ip]```
  4. Do: ```run```

## Scenarios

### Cisco UC520


```
msf5 > use auxiliary/scanner/sip/options_tcp 
msf5 auxiliary(scanner/sip/options_tcp) > set rhosts 2.2.2.2
rhosts => 2.2.2.2
msf5 auxiliary(scanner/sip/options_tcp) > run

[*] 2.2.2.2:5060    - 2.2.2.2:5060 tcp SIP/2.0 200 OK: {"Server"=>"Cisco-SIPGateway/IOS-12.x", "Allow"=>"INVITE, OPTIONS, BYE, CANCEL, ACK, PRACK, UPDATE, REFER, SUBSCRIBE, NOTIFY, INFO, REGISTER"}
[*] 2.2.2.2:5060    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Confirming using NMAP

Utilizing the [sip-methods](https://nmap.org/nsedoc/scripts/sip-methods.html) script

```
nmap --script=sip-methods -p 5060 2.2.2.2

Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-11 15:44 EDT
Nmap scan report for 2.2.2.2
Host is up (0.0036s latency).

PORT     STATE SERVICE
5060/tcp open  sip
|_sip-methods: INVITE, OPTIONS, BYE, CANCEL, ACK, PRACK, UPDATE, REFER, SUBSCRIBE, NOTIFY, INFO, REGISTER
MAC Address: 00:1B:8F:AA:AA:AA (Cisco Systems)
```

