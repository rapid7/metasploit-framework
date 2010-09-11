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
			TLVPacket ifaceTLV = new TLVPacket();
			byte[][] info = getIfaceCommand.getInformation(iface);
			if (info[0] != null) {
				ifaceTLV.add(TLVType.TLV_TYPE_SUBNET, info[0]);
				ifaceTLV.add(TLVType.TLV_TYPE_NETMASK, info[1]);
				ifaceTLV.add(TLVType.TLV_TYPE_GATEWAY, new byte[info[0].length]);
				response.addOverflow(TLVType.TLV_TYPE_NETWORK_ROUTE, ifaceTLV);
			}
		}
		return ERROR_SUCCESS;
	}
}
