Before submitting a pcap to [msfdev@metasploit.com](mailto:msfdev@metasploit.com), you may choose to sanitize it.  Mainly, you'll want to change the mac addresses and IP addresses.

## Kali Linux

`tcprewrite` can be used to change the IP and MAC addresses.  The following command will take care of both of those: `tcprewrite --seed=<int> --infile=<infile> --outfile=<outfile> --dlt=enet --enet-dmac=<dmac> --enet-smac=<smac>`

* `seed` is used to seed changes to IP address.  Pick a number for here, `111` is acceptable.
* `dlt` fixes an error: `dlt_linux_ssl plugin does not support packet encoding`
* `enet-dmac` fixes the destination mac. `00:00:00:00:00:00` works
* `enet-smac` fixes the source mac. `11:11:11:11:11:11` works
