Simple module to transmit a given frequency for a specified amount of seconds. This
code was ported from [AndrewMohawk](https://github.com/AndrewMohawk).

NOTE: Users of this module should be aware of their local laws,
regulations, and licensing requirements for transmitting on any
given radio frequency.


## Options ##

  **FREQ**

  Frequency to brute force.

  **BAUD**

  Baud rate.  Default: 4800

  **POWER**

  Power level to specify.  Default: 100

  **SECONDS**

  How many seconds to transmit the signal.  Default: 4

  **INDEX**

  USB Index number.  Default: 0

## Scenarios

  Transmit a given signal for 4 seconds

```
hwbridge > run post/hardware/rftransceiver/transmitter FREQ=433880000

[*] Transmitting on 433880000 for 4 seconds...
[*] Finished transmitting
```
