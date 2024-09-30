## Vulnerable Application

Many Kyocera multifunction printers (MFPs) can be administered using Net Viewer. Two such supported and tested models of MFPs are the ECOSYS M2640idw and the TASKalfa 406ci. These printers can be routinely found in both home office and enterprise environments around the world.

## Verification Steps


1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/kyocera_addressbook_credential_gather`
4. Set RHOSTS to target Kyocera printer
5. You should recieve the addressbook in XML format

## Options
RHOSTS - target host
RPORT - target port
TARGETURI - target URI of exposed addressbook
SSL - HTTP/S


## Scenarios
Kyocera printers with an enabled and populated address book oftentimes have Active Directory usernames and passwords conatined in them that you can dump with this module. 
### Version and OS

Kyocera ECOSYS M2640idw
Kyocera TASKalfa 406ci

