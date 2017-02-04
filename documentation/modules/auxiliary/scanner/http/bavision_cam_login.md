This module allows you to log into an BAVision IP Camera's web server.

The instructions shipped with the camera do not mention clearly regarding the existence of the
lighttpd web server, and it uses admin:123456 as the default credential. Even if the default
password is changed, the account could also be bruteforced since there is no policy for lockouts.


## Vulnerable Application

The web server is built into the IP camera. Specifically, this camera was tested during development:

"BAVISION 1080P HD Wifi Wireless IP Camera Home Security Baby Monitor Spy Pet/Dog Cameras Video Monitoring Plug/Play,Pan/Tilt With Two-Way Audio and Night Vision"

http://goo.gl/pHAqS1

## Verification Steps

  1. Read the instructions that come with the IP camera to set it up
  2. Find the IP of the camera (in lab, your router should have info about this)
  3. Do: ```use auxiliary/scanner/http/bavision_cam_login```
  4. Set usernames and passwords
  5. Do: ```run```

## Options

  **TRYDEFAULT**

  The ```TRYDEFAULT``` options adds the default credential admin:123456 to the credential list.
