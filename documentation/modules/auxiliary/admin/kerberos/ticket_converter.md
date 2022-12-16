# Kerberos Ticket Converting (CCache <---> Kirbi)

The `ticket_converter` module is used to convert from a ccache file format to the kirbi file format and vice versa.

## Pre-Verification steps

1. Obtain a ccache or kirbi file. You can use the `forge_ticket` module to forge a ccache file for this step.
    `use modules/auxiliary/admin/kerberos/forge_ticket`

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/admin/kerberos/ticket_converter`
3. Do: `set InputPath /path/to/ccache/or/kirbi/file`
4. Do: `set OutputPath /path/to/save/your/converted/file`
5. Do: `run`
6. You should see output similar to:
   ```
   [*] [2022.12.16-12:52:56] Converting from ccache to kirbi
   [*] [2022.12.16-12:52:56] File written to <OutputPath>
   [*] Auxiliary module execution completed
   ```
7. Use your ticket which will have been stored at <OutputPath>
8. Example usage in impacket:
   ```
   export KRB5CCNAME=/path/to/ccache/ticket
   python3 mssqlclient.py DW.LOCAL/fake_mysql@dc1.dw.local -k -no-pass
   ```
9. Alternatively you may use the `inspect_ticket` module to prints the contents of the ccache/kirbi file.
   `use auxiliary/admin/kerberos/inspect_ticket`

# Scenarios

## You have a ccache file

If you have a ccache file (for example by forging it using the `forge_ticket` module)
but need a file in the kirbi format which is commonly use by mimikatz.
Simply set the `InputPath` to the location of your ccache file, specify your
desired output location with `OutputPath` and `run`. 
We automatically detect the file type so there's no need to tell msfconsole 
whether it's a ccache or kirbi file.

## You have a kirbi file

The other scenario is if you have a kirbi file (for example mimikatz will give you tickets in the kirbi format)
and you need a ccache for use with another tool including Metasploit and Impacket.
The steps are exactly the same for a kirbi file as they are for a ccache since
we automatically detect the file type. Just set your `InputPath` to the location of 
your kirbi file and `OutputPath` to where you want the ccache file saved, `run` the module
and you're ready to go.
