HWBridge Tools
--------------
This folder contains hardware related tools that are compatible with the HWBridge interface.
Commonly this will be a repository of different hardware relay services.  If your device
requires communication via serial or USB or some other non-ethernet means and you want
to utilize the metasploit framework for handling the HTTP server then feel free to put
your relay here.

If however your device supports WiFi or Ethernet, then consider building the HWBridge
support directly into your hardware.  Check your development board to see if there is
a library available that supports your chipset and the MSF HWBridge.  Often the
library will be called MSF_Relay or something similar.
