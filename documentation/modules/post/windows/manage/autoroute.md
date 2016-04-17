## Overview

This module is used to add routes associated with the specified Meterpreter session to the Metasploit routing table. These routes can be used to pivot to private networks and resources that can be accessed by the compromised machine. This module can search for routes and add them automatically. Routes can also be added manually, deleted, or displayed.

## CMD Options
This module has several command "CMD" options that are used to control the module’s behavior.

### autoadd
This is the default behavior for this module. When this CMD option is used, the module searches the compromised machine's routing table and network interface list looking for networks that the machine can access. Once found, the module automatically adds routes to the networks to Metasploit’s routing table. Duplicate routes from new sessions are not added.

### add
This CMD option is used to manually add routes to the Metasploit routing table. An IPv4 subnet and netmask (IPv4 or CIDR) are required to add routes manually. The session number of the Meterpreter session to run the module on is also required.

Subnet Example `set SUBNET 192.168.1.0`

Netmask Examples `set NETMASK 255.255.255.0` or `set NETMASK /24`

### delete
This CMD option is used to remove a route from the Metasploit routing table. The IPv4 subnet and netmask (IPv4 or CIDR) of the route to be removed are required. The session number of the Meterpreter session to run the module on is also required. Use `route print` or the 'view' CMD option to display the current Metasploit routing table.

### print
This CMD option is used to display the current Metasploit routing table. This option has the same functionality as the `route print` command.

### default
This CMD option is used to add a default route to the Metasploit routing table that routes all TCP/IP traffic not otherwise covered in other routes through the specified session when pivoting. **Use this option with caution.**

This option is useful in special situations. An example would be when the compromised host is using a full traffic VPN where the VPN server does the routing to private networks. In this case, the routing table of the compromised host would likely not have entries for these private networks. Adding a default route would push the routing off to the VPN server, and those networks would likely become accessible.
