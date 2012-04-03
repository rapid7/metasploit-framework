package com.metasploit.meterpreter.stdapi;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_net_config_get_interfaces_V1_4 extends stdapi_net_config_get_interfaces implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		int index = 0;
		for (Enumeration ifaces = NetworkInterface.getNetworkInterfaces(); ifaces.hasMoreElements();) {
			NetworkInterface iface = (NetworkInterface) ifaces.nextElement();
			TLVPacket ifaceTLV = new TLVPacket();
			ifaceTLV.add(TLVType.TLV_TYPE_INTERFACE_INDEX, ++index);
			Address[] addresses = getAddresses(iface);
			for (int i = 0; i < addresses.length; i++) {
				ifaceTLV.addOverflow(TLVType.TLV_TYPE_IP, addresses[i].address);
				ifaceTLV.addOverflow(TLVType.TLV_TYPE_IP_PREFIX, new Integer(addresses[i].prefixLength));
				if (addresses[i].scopeId != null) {
					ifaceTLV.addOverflow(TLVType.TLV_TYPE_IP6_SCOPE, addresses[i].scopeId);
				}
			}
			addMTU(ifaceTLV, iface);
			byte[] mac = getMacAddress(iface);
			if (mac != null) {
				ifaceTLV.add(TLVType.TLV_TYPE_MAC_ADDRESS, mac);
			} else {
				// seems that Meterpreter does not like interfaces without
				// mac address
				ifaceTLV.add(TLVType.TLV_TYPE_MAC_ADDRESS, new byte[0]);
			}
			ifaceTLV.add(TLVType.TLV_TYPE_MAC_NAME, iface.getName() + " - " + iface.getDisplayName());
			response.addOverflow(TLVType.TLV_TYPE_NETWORK_INTERFACE, ifaceTLV);
		}
		return ERROR_SUCCESS;
	}

	protected void addMTU(TLVPacket ifaceTLV, NetworkInterface iface) throws IOException {
		// not supported before 1.6
	}

	protected byte[] getMacAddress(NetworkInterface iface) throws IOException {
		return null;
	}

	/**
	 * Return address information of this interface that cannot be determined
	 * the same way for all Java versions.
	 * 
	 * @param iface
	 * @return Array of {@link Interface}
	 */
	public Address[] getAddresses(NetworkInterface iface) throws IOException {
		List/* <Address> */result = new ArrayList();
		for (Enumeration en = iface.getInetAddresses(); en.hasMoreElements();) {
			InetAddress addr = (InetAddress) en.nextElement();
			byte[] ip = addr.getAddress();
			if (ip == null)
				continue;
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
			result.add(new Address(ip, prefixLength, null));
		}
		return (Address[]) result.toArray(new Address[result.size()]);
	}

	/**
	 * An IP address associated to an interface, together with a prefix length
	 * and optionally a scope.
	 */
	protected static class Address {
		public final byte[] address;
		public final int prefixLength;
		public final byte[] scopeId;

		public Address(byte[] address, int prefixLength, byte[] scopeId) {
			this.address = address;
			this.prefixLength = prefixLength;
			this.scopeId = scopeId;
		}
	}
}
