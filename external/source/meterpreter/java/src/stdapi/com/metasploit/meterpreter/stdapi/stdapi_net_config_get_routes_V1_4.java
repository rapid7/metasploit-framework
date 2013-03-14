package com.metasploit.meterpreter.stdapi;

import java.net.NetworkInterface;
import java.util.Enumeration;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_net_config_get_routes_V1_4 extends stdapi_net_config_get_routes implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		stdapi_net_config_get_interfaces_V1_4 getIfaceCommand = (stdapi_net_config_get_interfaces_V1_4) meterpreter.getCommandManager().getCommand("stdapi_net_config_get_interfaces");
		for (Enumeration ifaces = NetworkInterface.getNetworkInterfaces(); ifaces.hasMoreElements();) {
			NetworkInterface iface = (NetworkInterface) ifaces.nextElement();
			stdapi_net_config_get_interfaces_V1_4.Address[] addresses = getIfaceCommand.getAddresses(iface);
			for (int i = 0; i < addresses.length; i++) {
				TLVPacket ifaceTLV = new TLVPacket();
				ifaceTLV.add(TLVType.TLV_TYPE_SUBNET, addresses[i].address);
				int length = addresses[i].address.length;
				ifaceTLV.add(TLVType.TLV_TYPE_NETMASK, createNetworkMask(length, addresses[i].prefixLength));
				ifaceTLV.add(TLVType.TLV_TYPE_GATEWAY, new byte[length]);
				response.addOverflow(TLVType.TLV_TYPE_NETWORK_ROUTE, ifaceTLV);
			}
		}
		return ERROR_SUCCESS;
	}

	private static byte[] createNetworkMask(int length, int prefixLength) {
		if (prefixLength > length * 8)
			prefixLength = length * 8;
		byte[] netmask = new byte[length];
		for (int i = 0; i < prefixLength; i++) {
			netmask[i / 8] |= (1 << (7 - (i % 8)));
		}
		return netmask;
	}
}
