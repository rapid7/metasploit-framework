Actively scans the Zigbee channels by sending a beacon broadcast packet and listening for responses.

## Options

  **DEVICE**

  Zigbee Device ID.  Defaults to the target device that is specified via the target command or if
  one device is presented when runnign 'supported_devices' it will use that device.

  **CHANNEL**

  The Channel to scan.  This will prevent the stumbler from changing channels.  Range is 11-25

  **LOOP**

  How many times to loop over the channels.  Specifying a -1 will loop forever.  The default is once.

  **DELAY**

  The delay in seconds to listen to each channel.  The default is 2

## Scenarios

  Scanning channel 11 for other Zigbee devices in the area.

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
