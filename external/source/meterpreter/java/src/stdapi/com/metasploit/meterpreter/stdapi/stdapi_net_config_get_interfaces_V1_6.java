package com.metasploit.meterpreter.stdapi;

import java.io.IOException;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.Iterator;
import java.util.List;

public class stdapi_net_config_get_interfaces_V1_6 extends stdapi_net_config_get_interfaces_V1_4 {

	public byte[][] getInformation(NetworkInterface iface) throws IOException {
		byte[] ip = null;
		List addresses = iface.getInterfaceAddresses();
		int prefixLength = 0;
		for (Iterator it = addresses.iterator(); it.hasNext();) {
			InterfaceAddress addr = (InterfaceAddress) it.next();
			if (addr.getAddress().getAddress().length == 4) {
				ip = addr.getAddress().getAddress();
				prefixLength = addr.getNetworkPrefixLength();
				break;
			}
		}
		if (ip == null) {
			for (Iterator it = addresses.iterator(); it.hasNext();) {
				InterfaceAddress addr = (InterfaceAddress) it.next();
				ip = addr.getAddress().getAddress();
				prefixLength = addr.getNetworkPrefixLength();
				break;
			}
		}
		byte[] netmask = null;
		if (ip != null) {
			netmask = createNetworkMask(ip.length, prefixLength);
		}
		byte[] mac = iface.getHardwareAddress();
		if (mac == null)
			mac = new byte[6];
		return new byte[][] { ip, netmask, mac };
	}
}
