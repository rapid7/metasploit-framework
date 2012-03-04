package com.metasploit.meterpreter.stdapi;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_net_config_get_interfaces_V1_4 extends stdapi_net_config_get_interfaces implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		for (Enumeration ifaces = NetworkInterface.getNetworkInterfaces(); ifaces.hasMoreElements();) {
			NetworkInterface iface = (NetworkInterface) ifaces.nextElement();
			TLVPacket ifaceTLV = new TLVPacket();
			byte[][] info = getInformation(iface);
			if (info[0] != null) {
				ifaceTLV.add(TLVType.TLV_TYPE_IP, info[0]);
				ifaceTLV.add(TLVType.TLV_TYPE_NETMASK, info[1]);
			} else {
				ifaceTLV.add(TLVType.TLV_TYPE_IP, new byte[4]);
				ifaceTLV.add(TLVType.TLV_TYPE_NETMASK, new byte[4]);
			}
			try {
				ifaceTLV.add(TLVType.TLV_TYPE_MTU, iface.getMTU());
			} catch (NoSuchMethodError e) { }

			ifaceTLV.add(TLVType.TLV_TYPE_MAC_ADDRESS, info[2]);
			ifaceTLV.add(TLVType.TLV_TYPE_MAC_NAME, iface.getName() + " - " + iface.getDisplayName());
			response.addOverflow(TLVType.TLV_TYPE_NETWORK_INTERFACE, ifaceTLV);
		}
		return ERROR_SUCCESS;
	}

	/**
	 * Return information of this interface that cannot be determined the same way for all Java versions. Currently this includes ip, network mask and MAC address.
	 * 
	 * @param iface
	 * @return ip, network mask and MAC address
	 */
	public byte[][] getInformation(NetworkInterface iface) throws IOException {
		byte[] ip = null;
		for (Enumeration en = iface.getInetAddresses(); en.hasMoreElements();) {
			InetAddress addr = (InetAddress) en.nextElement();
			if (addr.getAddress().length == 4) {
				ip = addr.getAddress();
				break;
			}
		}
		if (ip == null) {
			for (Enumeration en = iface.getInetAddresses(); en.hasMoreElements();) {
				InetAddress addr = (InetAddress) en.nextElement();
				ip = addr.getAddress();
				break;
			}
		}
		byte[] netmask = null;
		if (ip != null) {
			int prefixLength = 0;
			if (ip.length == 4) {
				// guess netmask by network class...
				if ((ip[0] & 0xff) < 0x80) {
					prefixLength = 8;
				} else if ((ip[0] & 0xff) < 0xc0) {
					prefixLength = 16;
				} else {
					prefixLength = 24;
				}
			}
			netmask = createNetworkMask(ip.length, prefixLength);
		}
		return new byte[][] { ip, netmask, new byte[6] };
	}

	protected static byte[] createNetworkMask(int length, int prefixLength) {
		byte[] netmask = new byte[length];
		for (int i = 0; i < prefixLength; i++) {
			netmask[i / 8] |= (1 << (7 - (i % 8)));
		}
		return netmask;
	}
}

