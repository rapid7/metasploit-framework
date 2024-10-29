Actively scans the Zigbee channels by sending a beacon broadcast packet and listening for responses.

## Options

  **DEVICE**

  ZigBee Device ID.  Defaults to the target device that is specified via the target command or if
  one device is presented when running 'supported_devices' it will use that device.

  **CHANNEL**

  The channel to scan.  Setting this options will prevent the stumbler from changing channels.  Range is 11-26, inclusive.  Default: not set
n
  **LOOP**

  How many times to loop over the channels.  Specifying a -1 will loop forever.  Default: 1

  **DELAY**

  The delay in seconds to listen to each channel.  Default: 2

## Scenarios

  Scanning channel 11 for other ZigBee devices in the area.

```
hwbridge > run post/hardware/zigbee/zstumbler channel=11

[*] Scanning Channel 11
[*] New Network: PANID: 0x4724 SOURCE: 0x25D5
[*]         Ext PANID: 6E:03:C7:74:31:E2:74:AA       Stack Profile: ZigBee Enterprise
[*]         Stack Version: ZigBee 2006/2007
[*]         Channel: 11
[*] New Network: PANID: 0x4724 SOURCE: 0x7DD1
[*]         Ext PANID: 6E:03:C7:74:31:E2:74:AA       Stack Profile: ZigBee Enterprise
[*]         Stack Version: ZigBee 2006/2007
[*]         Channel: 11
```
