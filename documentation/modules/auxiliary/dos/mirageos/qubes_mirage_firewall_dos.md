## Vulnerable Application

The following versions of qubes-mirage-firewall (aka Mirage firewall for
QubesOS)

- 0.8.0 (588e921b9d78a99f6f49d468a7b68284c50dabeba95698648ea52e99b381723b)
- 0.8.1 (d0ec19d5b392509955edccf100852bcc9c0e05bf31f1ec25c9cc9c9e74c3b7bf)
- 0.8.2 (73488b0c54d6c43d662ddf58916b6d472430894f6394c6bdb8a879723abcc06f)
- 0.8.3 (f499b2379c62917ac32854be63f201e6b90466e645e54dea51e376baccdf26ab)

Vulnerable versions can be downloaded from
https://github.com/mirage/qubes-mirage-firewall/releases
Installation instruction is available at
https://github.com/mirage/qubes-mirage-firewall/blob/609f5295c7b315886244426b685807244c7dbe81/README.md#deploy

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use use auxiliary/dos/mirageos/qubes_mirage_firewall_dos`
1. Do: `run`
1. You should crash Mirage firewall

## Options

By default `RHOST` and `RPORT` are randomly chosen, but user can set arbitrary values.

### RHOST

`RHOST` should be in range of 239.255.0.0 to 239.255.255.255.

### RPORT

`RPORT` can be any value from 0 to 65535.

## Scenarios

Demo of the module is use is available at https://youtu.be/x3_vT1BcyOM

### Version and OS

Tested on Qubes release 4.1.1 (R4.1), with Mirage firewall version 0.8.3 build with Solo5 version 0.7.4.
