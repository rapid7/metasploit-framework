## Vulnerable Application

More information can be found on the [Rapid7 Blog](https://blog.rapid7.com/2010/03/08/locate-and-exploit-the-energizer-trojan).
Energizer's "DUO" USB Battery Charger included a backdoor which listens on port 7777.

The software can be downloaded from the [Wayback Machine](http://web.archive.org/web/20080722134654/www.energizer.com/usbcharger/language/english/download.aspx).

## Verification Steps

  1. Install the vulnerable software
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/backdoor/energizer_duo_detect`
  4. Do: `set rhosts`
  5. Do: `run`

## Scenarios

  A run against the backdoor

  ```
    msf > use auxiliary/scanner/backdoor/energizer_duo_detect
    msf auxiliary(energizer_duo_detect) > set RHOSTS 192.168.0.0/24
    msf auxiliary(energizer_duo_detect) > set THREADS 256
    msf auxiliary(energizer_duo_detect) > run

    [*] 192.168.0.132:7777 FOUND: [["F", "AUTOEXEC.BAT"]...
  ```
