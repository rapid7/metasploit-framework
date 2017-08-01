## Vulnerable Application

Chargen is a debugging and measurement tool and a character generator service.  Often `chargen` is included in `xinetd`,
along with `echo`, `time`, `daytime`, and `discard`.
While its possible to run chargen on TCP, the most common implementation is UDP.

The following was done on Kali linux:
  
  1. `apt-get install xinetd`
  2. edit `/etc/xinetd.d/chargen` and changed `disabled = yes` to `disabled = no`.  The first one is for `TCP` and the second is for `UDP`.
  3. Restart the service: `service xinetd restart`

## Verification Steps

  1. Install and configure chargen
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/chargen/chargen_probe`
  4. Do: `run`

## Scenarios

  A run against the configuration from these docs

  ```
    msf > use auxiliary/scanner/chargen/chargen_probe
    msf auxiliary(chargen_probe) > set rhosts 127.0.0.1
    rhosts => 127.0.0.1
    msf auxiliary(chargen_probe) > set verbose true
    verbose => true
    msf auxiliary(chargen_probe) > run
    
    [*] 127.0.0.1:19 - Response: !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefgh
    "#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghi
    #$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghij
    $%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijk
    %&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijkl
    &'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklm
    '()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmn
    ()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmno
    )*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnop
    *+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopq
    +,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqr
    ,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrs
    -./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrst
    ./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghi
    
    [+] 127.0.0.1:19 answers with 1022 bytes (headers + UDP payload)
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```
