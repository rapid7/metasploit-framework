# Vulnerable Application
Sagecom F@st-3890 Cable Modems

# Options

## WS_USERNAME
This is the basic auth username for the spectrum analysis web service.  This is typicall default credentials such as `admin:password` but may also be something along the lines of `spectrum:spectrum`.  This will vary from manufacturer to manufacturer and ISP to ISP.

## WS_PASSWORD
This is the basic auth password for the spectrum analysis web service.

## TIMEOUT
This is the timeout in seconds that the module should wait before making a conclusion on the success of the payload delivery.  Typically, the device crashes within about 5 second of the payload being delivered.  The default value of `15` should be seen as the lower bound for `TIMEOUT` values.

## RHOSTS
Typically the only address which should be used for this value is `192.168.100.1`. It can be different, but not in a well-secured configuration.

## RPORT
On some devices the Spectrum Analysis web service runs on port `8080`, though Lyrebirds (the original discoverer and PoC author) notes that sometimes it can run on port `6080`.

# Scenarios

```
msf5 auxiliary(dos/http/cable_haunt_websocket_dos) > run
[*] Running module against 192.168.100.1

[*] Attempting Connection to 192.168.100.1
[*] Opened connection
[*] Sending payload
[*] Checking Modem Status
[*] Cable Modem unreachable
[+] Exploit delivered and cable modem unreachable.
[*] Auxiliary module execution completed
```

# Notes
Please note that successful completion of this module will most likely knock out upstream network services, including any remote sessions connected through the cable modem.

Please refer to [https://cablehaunt.com/](https://cablehaunt.com/) for more information on this vulnerability.
