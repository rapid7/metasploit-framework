## Introduction
The `shodan_honeyscore` module utilizes the [Shodan](https://www.shodan.io/) API to determine whether or not a server is a honeypot.
When setting the module options, we aren't directly requesting `TARGET`, we are requesting the Shodan API to analyze `TARGET` and return a honeyscore from 0.0 to 1.0. 0.0 being `not a honeypot` and 1.0 being a `honeypot`. The original website for the honeypot system can be found here: https://honeyscore.shodan.io/.

#### NOTE:
In order for this module to function properly, a Shodan API key is needed. You can register for a free account here: https://account.shodan.io/register

## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/gather/shodan_honeyscore`
  3. Do: `set TARGET <targetip>`
  4. Do: `set SHODAN_APIKEY <your apikey>`
  5. Do: `run`
  6. If the API is up, you should receive a score from 0.0 to 1.0. (1.0 being a honeypot)

## Options

  **TARGET**

  The remote host to request the API to scan.

  **SHODAN_APIKEY**

  This is the API key you receive when signing up for a Shodan account. It should be a 32 character string of random letters and numbers.


## Scenarios

Running the module against a real system (in this case, the Google DNS server):

  ```
  msf > use auxiliary/gather/shodan_honeyscore
msf auxiliary(shodan_honeyscore) > options

Module options (auxiliary/gather/shodan_honeyscore):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   SHODAN_APIKEY                   yes       The SHODAN API key
   TARGET                          yes       The target to get the score of

msf auxiliary(shodan_honeyscore) > set TARGET 8.8.8.8
TARGET => 8.8.8.8
msf auxiliary(shodan_honeyscore) > set SHODAN_APIKEY [redacted]
SHODAN_APIKEY => [redacted]
msf auxiliary(shodan_honeyscore) > run

[*] Scanning 8.8.8.8
[-] 8.8.8.8 is not a honeypot
[*] 8.8.8.8 honeyscore: 0.0/1.0
[*] Auxiliary module execution completed
  ```
