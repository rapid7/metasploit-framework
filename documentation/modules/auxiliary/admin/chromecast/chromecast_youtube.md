This module plays (by default) ["Epic sax guy 10 hours"](https://www.youtube.com/watch?v=kxopViU98Xo) on a target Google Chromecast via YouTube.

Naturally, audio should be cranked to 11 before running this module.

Only the deprecated DIAL protocol is supported by this module. Casting via the newer CASTV2 protocol is unsupported at this time.

## Verification Steps

1. Do: ```use auxiliary/admin/chromecast/chromecast_youtube```
2. Do: ```set RHOST [IP]```
3. Do: ```run```

## Options

  **VID**

  The YouTube video to be played.  Defaults to [kxopViU98Xo](https://www.youtube.com/watch?v=kxopViU98Xo)

## Scenarios

### 1st generation Google Chromecast (USB stick looking, not circular)

```
msf > auxiliary/admin/chromecast/chromecast_youtube
msf auxiliary(chromecast_youtube) > set rhost 10.10.10.196
rhost => 10.10.10.196
msf auxiliary(chromecast_youtube) > run

[+] Playing https://www.youtube.com/watch?v=kxopViU98Xo
[*] Auxiliary module execution completed
```
