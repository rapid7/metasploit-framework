Port of a brute force utility by Corey Harding of LegacySecurityGroup.com, the original can be found
[here](https://github.com/exploitagency/github-rfpwnon/blob/master/rfpwnon.py).
It's a generic AM/OOK brute forcer with PWM translations.  It has been
demonstrated to work against static key garage door openers.

## Options

  **FREQ**

  Frequency to brute force.

  **BAUD**

  Baud rate.  Default: 2000

  **BINLENGTH**

  Binary bit-length for bruteforcing.  Default: 8

  **REPEAT**

  How many times to repeat the sending of the packet.  Default: 5

  **PPAD**

  Binary data to append to packet.  (Example: "0101")  Default: None

  **TPAD**

  Binary data to add to end of packet.  (Example: "0101")  Default: None

  **RAW**

  Do not do PWM encoding on packet.  Default: False

  **TRI**

  Use trinary signals.  Default: False

  **EXTRAVERBOSE**

  Adds some extra status messages.

  **INDEX**

  USB Index number.  Default: 0

  **DELAY**

  How many milliseconds to delay before transmission.  Too fast tends to lock up the device.  Default: 500 (0.5 seconds)

## Scenarios

  Run a brute force of 6 characters long with 2 repeats:

```
hwbridge > run post/hardware/rftransceiver/rfpwnon FREQ=915000000 BINLEGTH=6 REPEAT=2

[*] Generating de bruijn sequence...
[*] Brute forcing frequency: 915000000
[*] Transmitting...
[*] Binary before PWM encoding:
[*] 00000000
[*] Binary after PWM encoding:
[*] 11101110111011101110111011101110
[*] Transmitting...
[*] Binary before PWM encoding:
[*] 00000000
[*] Binary after PWM encoding:
[*] 11101110111011101110111011101110
[*] Transmitting...
[*] Binary before PWM encoding:
[*] 00000001
[*] Binary after PWM encoding:
[*] 11101110111011101110111011101000
[*] Transmitting...
[*] Binary before PWM encoding:
[*] 00000001
[*] Binary after PWM encoding:
[*] 11101110111011101110111011101000
[*] Transmitting...
[*] Binary before PWM encoding:
[*] 00000010
[*] Binary after PWM encoding:
[*] 11101110111011101110111010001110
[*] Transmitting...
...
```
