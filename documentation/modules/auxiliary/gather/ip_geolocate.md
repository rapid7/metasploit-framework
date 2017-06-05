The `ip_geolocate` module utilized a free IP based geolocation API from https://freegeoip.net. IPv4 and IPv6 is supported,
but the API sometimes trips up on IPv6. A list of IP addresses or a single address can be provided in the `RHOSTS` datastore option. 


## Options

  **RHOSTS**

  A list of IPv4 or IPv6 addresses or a single address to query the API for. The addresses will be checked when the module is executed.

## Scenarios
 
Example console output of scanning the Google DNS servers (IPv4 and IPv6)
```
msf > use auxiliary/gather/ip_geolocate
msf auxiliary(ip_geolocate) > options

Module options (auxiliary/gather/ip_geolocate):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       A comma separated list of addresses to scan

msf auxiliary(ip_geolocate) > set RHOSTS 8.8.8.8, 2001:4860:4860::8888
RHOSTS => 8.8.8.8, 2001:4860:4860::8888
msf auxiliary(ip_geolocate) > run


[*] Data for 8.8.8.8
  Country: United States (US)
  City: California (CA)
  Zip Code: 94035
  Latitude: 37.386 (estimation)
  Longitude: -122.0838 (estimation)
  Google Maps URL: https://maps.google.com/?q=37.386,-122.0838

[*] Data for 2001:4860:4860::8888
  Country: United States (US)
  City:  ()
  Zip Code: 
  Latitude: 37.751 (estimation)
  Longitude: -97.822 (estimation)
  Google Maps URL: https://maps.google.com/?q=37.751,-97.822
[*] Auxiliary module execution completed
```
