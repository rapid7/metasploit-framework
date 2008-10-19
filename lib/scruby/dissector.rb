#!/usr/bin/env ruby
# Copyright (C) 2007 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 

module Scruby

	# Track dissectors
	@@dissectors = {}
	
	def Scruby.register_dissector(cls)
		@@dissectors[cls.to_s.split('::')[-1]] = cls
	end
	
	def Scruby.dissectors
		@@dissectors
	end
	
	def Scruby.get_dissector(d)
		
		if(@@dissectors[d])
			return @@dissectors[d]
		end
		
		d = d.split('::')[-1]
		@@dissectors[d]
	end

	
	# Dissector for Ethernet
	class Ether<Layer
		Scruby.register_dissector(self)

		attr_accessor :dst, :src, :type

		def init
			@protocol = 'Ethernet'
			@fields_desc =  [ MACField('dst', ETHERADDR_ANY),
								MACField('src', ETHERADDR_ANY),
								XShortEnumField('type', ETHERTYPE_IPv4, ETHERTYPE_ALL) ]
		end
		
	end

	# Dissector for ARP 
	class ARP<Layer
		Scruby.register_dissector(self)
		def method_missing(method, *args)
			return Scruby.field(method, *args)
		end
	  
		attr_accessor  :hw_type, :ptype, :hwlen, :plen, :op, :hwsrc, :psrc, :pdst, :hwdst, :pdst

		@@request = {"who-has"=>1, "is-at"=>2, "RARP-req"=>3, "RARP-rep"=>4, 
				"Dyn-RARP-req"=>5, "Dyn-RAR-rep"=>6, "Dyn-RARP-err"=>7, 
				"InARP-req"=>8, "InARP-rep"=>9}

		def init
			@protocol = 'ARP'
			@fields_desc = [ XShortField("hwtype", 0x0001), 
					XShortEnumField("ptype",  ETHERTYPE_IPv4, ETHERTYPE_ALL),
					ByteField("hwlen", 6), 
					ByteField("plen", 4),  
					ShortField("op", @@request["who-has"]),   
					MACField("hwsrc", '00:00:00:00:00:00'), 
					IPField("psrc", '127.0.0.1'),            
					MACField("hwdst", '00:00:00:00:00:00'),     
					IPField("pdst", '127.0.0.1') ]            
		end

		def pre_send(underlayer, payload)
			if underlayer.is_a?(Ether)
				underlayer.type = ETHERTYPE_ARP
			end
		end
	end

	# Dissector for IPv4
	class IP<Layer
		Scruby.register_dissector(self)
		
		attr_accessor :version, :ihl, :tos, :len, :id, :flags, :frag
		attr_accessor :ttl, :proto, :chksum, :src, :dst

		def init
			@protocol = 'IPv4'
			@fields_desc = [ BitField('version', 4, 4),
							BitField('ihl', 5, 4),
							XByteField('tos', 0),
							ShortField('len', 20),
							XShortField('id', 0),
							FlagsField('flags', 0, 3, IPFLAGS),
							BitField('frag', 0, 13),
							ByteField('ttl', 64),
							ByteEnumField('proto', IPPROTO_TCP, IPPROTO_ALL),
							XShortField('chksum', 0),
							IPField('src', '127.0.0.1'),
							IPField('dst', '127.0.0.1') ]
		end

		def pre_send(underlayer, payload)
			# Total length
			self.len = 20 + payload.length

			# Checksum
			self.chksum = 0
			self.chksum = Layer.checksum(self.to_net())
		end

	end

	# Dissector for ICMP
	class ICMP<Layer
		Scruby.register_dissector(self)
		
		attr_accessor :type, :code, :chksum, :id, :seq

		def init
			@protocol = 'ICMP'
			@fields_desc = [ ByteEnumField('type', ICMPTYPE_ECHO_REQ, ICMPTYPE_ALL),
							ByteField('code', 0),
							XShortField('chksum', 0),
							XShortField('id', 0),
							XShortField('seq', 0) ]
		end

		def pre_send(underlayer, payload)
			# Checksum
			self.chksum = 0
			self.chksum = Layer.checksum(self.to_net() + payload)
		end

	end

	# Dissector for Raw
	class Raw<Layer
		Scruby.register_dissector(self)
		
		attr_accessor :load

		def init
			@protocol = 'Raw data'
			@fields_desc = [ StrField('load', '') ]
		end

	end

	# Dissector for TCP
	class TCP<Layer
		Scruby.register_dissector(self)

		attr_accessor :sport, :dport, :seq, :ack, :dataofs, :reserved
		attr_accessor :flags, :window, :chksum, :urgptr

		def init
			@protocol = 'TCP'
			@fields_desc = [ ShortField('sport', 1024),
							ShortField('dport', 80),
							IntField('seq', 0),
							IntField('ack', 0),
							BitField('dataofs', 5, 4),
							BitField('reserved', 0, 4),
							FlagsField('flags', 0x2, 8, TCPFLAGS),
							ShortField('window', 8192),
							XShortField('chksum', 0),
							ShortField('urgptr', 0) ]
		end

		def pre_send(underlayer, payload)

			# To compute the TCP checksum, the IP underlayer is needed.
			# Otherwise, the chksum field is left equal to 0.
			if underlayer.is_a?(IP)

				# Getting IP addresses from the IPFields
				ip_src = underlayer.fields_desc[10].to_net(underlayer.fields_desc[10])
				ip_dst = underlayer.fields_desc[11].to_net(underlayer.fields_desc[11])

				this_packet = self.to_net()

				pseudo_header = [ip_src,
								ip_dst,
								underlayer.proto,
								(this_packet + payload).length
								].pack("a4a4nn")

				self.chksum = 0
				self.chksum = Layer.checksum(pseudo_header + this_packet + payload)
			end
		end

	end

	# Dissector for UDP
	class UDP<Layer
		Scruby.register_dissector(self)
		
		attr_accessor :sport, :dport, :len, :chksum

		def init
			@protocol = 'UDP'
			@fields_desc = [ ShortField('sport', 53),
							ShortField('dport', 53),
							ShortField('len', 8),
							XShortField('chksum', 0) ]
		end

		# Almost the same as TCP
		def pre_send(underlayer, payload)

			# Total length
			self.len = 8 + payload.length

			# To compute the UDP checksum, the IP underlayer is needed.
			# Otherwise, the chksum field is left equal to 0.
			if underlayer.is_a?(IP)

				# Getting IP addresses from the IPFields
				ip_src = underlayer.fields_desc[10].to_net(underlayer.fields_desc[10])
				ip_dst = underlayer.fields_desc[11].to_net(underlayer.fields_desc[11])

				this_packet = self.to_net()

				pseudo_header = [ip_src,
								ip_dst,
								underlayer.proto,
								(this_packet + payload).length
								].pack("a4a4nn")

				self.chksum = 0
				self.chksum = Layer.checksum(pseudo_header + this_packet + payload)
			end
		end

	end

	# Dissector for the classic BSD loopback header (NetBSD, FreeBSD and Mac OS X)
	class ClassicBSDLoopback<Layer
		Scruby.register_dissector(self)
		
		attr_accessor :header

		def init
			@protocol = 'Classic BSD loopback'
			@fields_desc = [ HostOrderIntField('header', BSDLOOPBACKTYPE_IPv4) ]
		end

	end

	# Dissector for the OpenBSD loopback header
	class OpenBSDLoopback<Layer
		Scruby.register_dissector(self)
		
		attr_accessor :header

		def init
			@protocol = 'OpenBSD loopback'
			@fields_desc = [ LEIntField('header', BSDLOOPBACKTYPE_IPv4) ]
		end

	end


	# Dissector for the Prism header
	class Prism<Layer
		Scruby.register_dissector(self)
		
		attr_accessor :header

		def init
			@protocol = 'Prism'
			@fields_desc = [ 
				LEIntField("msgcode",68),
				LEIntField("len",144),
				StrFixedLenField("dev","",16),
				LEIntField("hosttime_did",0),
				LEShortField("hosttime_status",0),
				LEShortField("hosttime_len",0),
				LEIntField("hosttime",0),
				LEIntField("mactime_did",0),
				LEShortField("mactime_status",0),
				LEShortField("mactime_len",0),
				LEIntField("mactime",0),
				LEIntField("channel_did",0),
				LEShortField("channel_status",0),
				LEShortField("channel_len",0),
				LEIntField("channel",0),
				LEIntField("rssi_did",0),
				LEShortField("rssi_status",0),
				LEShortField("rssi_len",0),
				LEIntField("rssi",0),
				LEIntField("sq_did",0),
				LEShortField("sq_status",0),
				LEShortField("sq_len",0),
				LEIntField("sq",0),
				LEIntField("signal_did",0),
				LEShortField("signal_status",0),
				LEShortField("signal_len",0),
				LESignedIntField("signal",0),
				LEIntField("noise_did",0),
				LEShortField("noise_status",0),
				LEShortField("noise_len",0),
				LEIntField("noise",0),
				LEIntField("rate_did",0),
				LEShortField("rate_status",0),
				LEShortField("rate_len",0),
				LEIntField("rate",0),
				LEIntField("istx_did",0),
				LEShortField("istx_status",0),
				LEShortField("istx_len",0),
				LEIntField("istx",0),
				LEIntField("frmlen_did",0),
				LEShortField("frmlen_status",0),
				LEShortField("frmlen_len",0),
				LEIntField("frmlen",0)
			]
		end

	end
		
	# Dissector for RIFF file format header
	class RIFF<Layer
		Scruby.register_dissector(self)

		attr_accessor :id, :size, :headerid

		def init
			@protocol = 'RIFF chunk'
			@fields_desc = [ StrFixedLenField('id', 'RIFF', 4),
							LEIntField('size', 0),
							StrFixedLenField('headerid', 'ACON', 4) ]
		end

	end

	# Dissector for ANI header chunk  format
	class ANI<Layer
		Scruby.register_dissector(self)
		
		attr_accessor :id, :size, :headersize, :frames, :steps, :width, :height, :bitcount, :planes
		attr_accessor :displayrate, :reserved, :sequence, :icon

		def init
			@protocol = 'ANI chunk'
			@fields_desc = [ StrFixedLenField('id', 'anih', 4),
							LEIntField('size', 36),
							LEIntField('headersize', 36),
							LEIntField('frames', 2),
							LEIntField('steps', 0),
							LEIntField('width', 0),
							LEIntField('height', 0),
							LEIntField('bitcount', 0),
							LEIntField('planes', 0),
							LEIntField('displayrate', 0),
							BitField('icon', 0, 1),
							BitField('sequence', 0, 1),
							BitField('reserved', 0, 30) ]
		end

	end



	# Dot11 dissectors
	class RadioTap<Layer
		Scruby.register_dissector(self)

		attr_accessor :version, :pad, :len, :notdecoded, :present

		def init
			@protocol = 'RadioTap'
			@fields_desc = [ ByteField('version', 0),
							ByteField('pad', 0),
							FieldLenField('len', 0, 'radiotap', 's', { :adjust => -8 } ),
							FlagsField('present', 0, 32, RADIOTAP_PRESENT),
							StrLenField('radiotap', '', 'len')
			               ]
		end

	end
	
	
	# Dot11 dissectors
	class Dot11<Layer
		Scruby.register_dissector(self)

		attr_accessor :subtype, :type, :proto, :FCfield, :ID, :addr1, :addr2, :addr3, :SC, :addr4

		def init
			@protocol = '802.11'
			@fields_desc = [ BitField('subtype', 0, 4),
							BitEnumField('type', DOT11TYPE_DATA, 2, DOT11TYPE_ALL),
							BitField('proto', 0, 2),
							FlagsField('FCfield', 0, 8, DOT11_FC_FLAGS),
							ShortField('ID', 0),
							MACField('addr1', ETHERADDR_ANY),
							Dot11Addr2MACField('addr2', ETHERADDR_ANY),
							Dot11Addr3MACField('addr3', ETHERADDR_ANY),
							Dot11SCField('SC', 0),
							Dot11Addr4MACField('addr4', ETHERADDR_ANY) ]
		end

	end

	class Dot11QoS<Layer
		Scruby.register_dissector(self)

		attr_accessor :TID, :EOSP, :AckPolicy, :Reserved, :TXOP

		def init
			@protocol = '802.11 QoS'
			@fields_desc = [ BitField('TID',0,4),
							BitField('EOSP',0,1),
							BitField('AckPolicy',0,2),
							BitField('Reserved',0,1),
							ByteField('TXOP',0) ]
		end

	end

	class Dot11Beacon<Layer
		Scruby.register_dissector(self)

		attr_accessor :timestamp, :beacon_interval, :cap

		def init
			@protocol = '802.11 Beacon'
			@fields_desc = [ LongField('timestamp', 0), # Bug: should be little endian
							LEShortField('beacon_interval', 0x64),
							FlagsField('cap', 0, 16, DOT11_CAPABILITIES) ]
		end

	end

	class Dot11Elt<Layer
		Scruby.register_dissector(self)

		attr_accessor :ID, :len, :info

		def init
			@protocol = '802.11 Information Element'
			@fields_desc = [ ByteEnumField('ID', 0, DOT11_ID),
							FieldLenField('len', 0, 'info', 'C'),
							StrLenField('info', '', 'len') ]
		end

	end

	class Dot11ATIM<Layer
		Scruby.register_dissector(self)

		def init
			@protocol = '802.11 ATIM'
		end
	end

	class Dot11Disas<Layer
		Scruby.register_dissector(self)

		attr_accessor :reason

		def init
			@protocol = '802.11 Disassociation'
			@fields_desc = [ LEShortEnumField('reason', 1, DOT11_REASON) ]
		end

	end

	class Dot11AssoReq<Layer
		Scruby.register_dissector(self)

		attr_accessor :cap, :listen_interval

		def init
			@protocol = '802.11 Association Request'
			@fields_desc = [ FlagsField('cap', 0, 16, DOT11_CAPABILITIES),
							LEShortField('listen_interval', 0xc8) ]
		end

	end

	class Dot11AssoResp<Layer
		Scruby.register_dissector(self)

		attr_accessor :cap, :status, :AID

		def init
			@protocol = '802.11 Association Response'
			@fields_desc = [ FlagsField('cap', 0, 16, DOT11_CAPABILITIES),
							LEShortField('status', 0),
							LEShortField('AID', 0) ]
		end

	end

	class Dot11ReassoReq<Layer
		Scruby.register_dissector(self)

		attr_accessor :cap, :current_AP, :listen_interval

		def init
			@protocol = '802.11 Reassociation Request'
			@fields_desc = [ FlagsField('cap', 0, 16, DOT11_CAPABILITIES),
							MACField('current_AP', ETHERADDR_ANY),
							LEShortField('listen_interval', 0xc8) ]
		end

	end

	class Dot11ReassoResp<Dot11AssoResp
		Scruby.register_dissector(self)

		def init
			@protocol = '802.11 Reassociation Response'
		end
	end

	class Dot11ProbeReq<Layer
		Scruby.register_dissector(self)

		def init
			@protocol = '802.11 Probe Request'
		end
	end

	class Dot11ProbeResp<Layer
		Scruby.register_dissector(self)

		attr_accessor :timestamp, :beacon_interval, :cap

		def init
			@protocol = '802.11 Probe Response'
			@fields_desc = [ LongField('timestamp', 0), # Bug: should be little endian
							LEShortField('beacon_interval', 0x64),
							FlagsField('cap', 0, 16, DOT11_CAPABILITIES) ]
		end

	end

	class Dot11Auth<Layer
		Scruby.register_dissector(self)

		attr_accessor :algo, :seqnum, :status

		def init
			@protocol = '802.11 Authentication'
			@fields_desc = [ LEShortEnumField('algo', 0, DOT11_AUTH_ALGO),
							LEShortField('seqnum', 0),
							LEShortEnumField('status', 0, DOT11_STATUS) ]
		end

	end

	class Dot11Deauth<Layer
		Scruby.register_dissector(self)

		attr_accessor :reason

		def init
			@protocol = '802.11 Deauthentication'
			@fields_desc = [ LEShortEnumField('reason', 1, DOT11_REASON) ]
		end

	end

	class Dot11WEP<Layer
		Scruby.register_dissector(self)

		attr_accessor :iv, :keyid, :wepdata, :icv

		def init
			@protocol = '802.11 WEP packet'
			@fields_desc = [ StrFixedLenField('iv', "\0\0\0", 3),
							ByteField('keyid', 0),
							StrField('wepdata', ''), # Bug: 4 bytes remains
							IntField('icv', 0) ]
		end

	end

	class LLC<Layer
		Scruby.register_dissector(self)

		attr_accessor :dsap, :ssap, :ctrl

		def init
			@protocol = 'LLC'
			@fields_desc = [ XByteField('dsap', 0),
							XByteField('ssap', 0),
							ByteField('ctrl', 0) ]
		end

	end

	# Layer bounds
	@@layer_bounds =
	{
		'Ether' => 
		[
			['type', ETHERTYPE_IPv4, IP],
			['type', ETHERTYPE_ARP, ARP]
		],
		
		'RadioTap' =>
		[
			[BIND_ALWAYS, BIND_ALWAYS, Dot11]
		],
		
		'Prism' =>
		[
			[BIND_ALWAYS, BIND_ALWAYS, Dot11]
		],

		'Dot11' => [
			['type', 2, LLC],
			['subtype', 0, Dot11AssoReq],
			['subtype', 1, Dot11AssoResp],
			['subtype', 2, Dot11ReassoReq],
			['subtype', 3, Dot11ReassoResp],
			['subtype', 4, Dot11ProbeReq],
			['subtype', 5, Dot11ProbeResp],
			['subtype', 8, Dot11Beacon],
			['subtype', 9, Dot11ATIM],
			['subtype', 10, Dot11Disas],
			['subtype', 11, Dot11Auth],
			['subtype', 12, Dot11Deauth],
		],

		'Dot11QoS' => [
			[BIND_ALWAYS, BIND_ALWAYS, LLC]
		],
		'Dot11Beacon' => [
			[BIND_ALWAYS, BIND_ALWAYS, Dot11Elt]
		],
		'Dot11AssoReq' => [
			[BIND_ALWAYS, BIND_ALWAYS, Dot11Elt]
		],
		'Dot11AssoResp' => [
			[BIND_ALWAYS, BIND_ALWAYS, Dot11Elt]
		],
		'Dot11ReassoReq' => [
			[BIND_ALWAYS, BIND_ALWAYS, Dot11Elt]
		],
		'Dot11ReassoResp' => [
			[BIND_ALWAYS, BIND_ALWAYS, Dot11Elt]
		],
		'Dot11ProbeReq' => [
			[BIND_ALWAYS, BIND_ALWAYS, Dot11Elt]
		],
		'Dot11ProbeResp' => [
			[BIND_ALWAYS, BIND_ALWAYS, Dot11Elt]
		],
		'Dot11Auth' => [
			[BIND_ALWAYS, BIND_ALWAYS, Dot11Elt]
		],
		'Dot11Elt' => [
			[BIND_ALWAYS, BIND_ALWAYS, Dot11Elt]
		],
		
		'ClassicBSDLoopback' => 
		[
			['header', BSDLOOPBACKTYPE_IPv4, IP]
		],

		'OpenBSDLoopback' => 
		[
			['header', BSDLOOPBACKTYPE_IPv4, IP]
		],

		'IP' => 
		[
			['proto', IPPROTO_ICMP, ICMP],
			['proto', IPPROTO_TCP, TCP],
			['proto', IPPROTO_UDP, UDP]
		],
	}

	def self.layer_bounds
		@@layer_bounds
	end

	
	def Scruby.linklayer_dissector(datalink, pkt)
		case datalink
		when Pcap::DLT_EN10MB
			Ether(pkt)
		when Pcap::DLT_NULL
			ClassicBSDLoopback(pkt)
		when DLT_OPENBSD
			OpenBSDLoopback(pkt)
		when Pcap::DLT_PRISM_HEADER
			Prism(pkt)
		when Pcap::DLT_IEEE802
		when Pcap::DLT_IEEE802_11
			Dot11(pkt)
		when Pcap::DLT_IEEE802_11_RADIO
			RadioTap(pkt)
		when Pcap::DLT_IEEE802_11_RADIO_AVS
			RadioTap(pkt)	
		when 101,
			IP(pkt)			
		else
			nil
		end
	end
	
end

=begin

Scruby packet dissectors/types:
===============================
	ANI
	ARP
	ClassicBSDLoopback
	Ether
	ICMP
	IP
	OpenBSDLoopback
	RIFF
	Raw
	TCP
	UDP
	LLC
	ARP
	Prism
	Dot11
	Dot11Beacon
        Dot11Elt
        Dot11ATIM
        Dot11Disas
        Dot11AssoReq
        Dot11AssoResp
        Dot11ReassoReq
        Dot11ReassoResp
        Dot11ProbeReq
        Dot11ProbeResp
        Dot11Auth
        Dot11Deauth
        Dot11WEP

Scapy (1.2.0.1) packet dissectors/types:
========================================
	Raw
	Padding
	Ether
	PPPoE
	PPPoED
	Dot3
	LLC
	CookedLinux
	SNAP
	Dot1Q
	RadioTap
	STP
	EAPOL
	EAP
	ARP
	IP
	TCP
	UDP
	ICMP
	IPerror
	TCPerror
	UDPerror
	ICMPerror
	IPv6
	_IPv6OptionHeader
	PPP
	DNS
	DNSQR
	DNSRR
	BOOTP
	DHCPOptionsField
	DHCP
	Dot11
	Dot11Beacon
	Dot11Elt
	Dot11ATIM
	Dot11Disas
	Dot11AssoReq
	Dot11AssoResp
	Dot11ReassoReq
	Dot11ReassoResp
	Dot11ProbeReq
	Dot11ProbeResp
	Dot11Auth
	Dot11Deauth
	Dot11WEP
	PrismHeader
	HSRP
	NTP
	GRE
	Radius
	RIP
	RIPEntry
	ISAKMP_class
	ISAKMP
	ISAKMP_payload_Transform
	ISAKMP_payload_Proposal
	ISAKMP_payload
	ISAKMP_payload_VendorID
	ISAKMP_payload_SA
	ISAKMP_payload_Nonce
	ISAKMP_payload_KE
	ISAKMP_payload_ID
	ISAKMP_payload_Hash
	Skinny
	RTP
	SebekHead
	SebekV1
	SebekV3
	SebekV2
	SebekV3Sock
	SebekV2Sock
	MGCP
	GPRS
	HCI_Hdr
	HCI_ACL_Hdr
	L2CAP_Hdr
	L2CAP_CmdHdr
	L2CAP_ConnReq
	L2CAP_ConnResp
	L2CAP_CmdRej
	L2CAP_ConfReq
	L2CAP_ConfResp
	L2CAP_DisconnReq
	L2CAP_DisconnResp
	L2CAP_InfoReq
	L2CAP_InfoResp
	NetBIOS_DS
	IrLAPHead
	IrLAPCommand
	IrLMP
	NBNSQueryRequest
	NBNSRequest
	NBNSQueryResponse
	NBNSQueryResponseNegative
	NBNSNodeStatusResponse
	NBNSNodeStatusResponseService
	NBNSNodeStatusResponseEnd
	NBNSWackResponse
	NBTDatagram
	NBTSession
	SMBNetlogon_Protocol_Response_Header
	SMBMailSlot
	SMBNetlogon_Protocol_Response_Tail_SAM
	SMBNetlogon_Protocol_Response_Tail_LM20
	SMBNegociate_Protocol_Request_Header
	SMBNegociate_Protocol_Request_Tail
	SMBNegociate_Protocol_Response_Advanced_Security
	SMBNegociate_Protocol_Response_No_Security
	SMBNegociate_Protocol_Response_No_Security_No_Key
	SMBSession_Setup_AndX_Request
	SMBSession_Setup_AndX_Response
	MobileIP
	MobileIPRRQ
	MobileIPRRP
	MobileIPTunnelData
	NetflowHeader
	NetflowHeaderV1
	NetflowRecordV1
	TFTP
	TFTP_RRQ
	TFTP_WRQ
	TFTP_DATA
	TFTP_Option
	TFTP_Options
	TFTP_ACK
	TFTP_ERROR
	TFTP_OACK
	ASN1_Class_SNMP
	ASN1_SNMP_PDU_GET
	ASN1_SNMP_PDU_NEXT
	ASN1_SNMP_PDU_RESPONSE
	ASN1_SNMP_PDU_SET
	ASN1_SNMP_PDU_TRAPv1
	ASN1_SNMP_PDU_BULK
	ASN1_SNMP_PDU_INFORM
	ASN1_SNMP_PDU_TRAPv2
	BERcodec_SNMP_PDU_GET
	BERcodec_SNMP_PDU_NEXT
	BERcodec_SNMP_PDU_RESPONSE
	BERcodec_SNMP_PDU_SET
	BERcodec_SNMP_PDU_TRAPv1
	BERcodec_SNMP_PDU_BULK
	BERcodec_SNMP_PDU_INFORM
	BERcodec_SNMP_PDU_TRAPv2
	ASN1F_SNMP_PDU_GET
	ASN1F_SNMP_PDU_NEXT
	ASN1F_SNMP_PDU_RESPONSE
	ASN1F_SNMP_PDU_SET
	ASN1F_SNMP_PDU_TRAPv1
	ASN1F_SNMP_PDU_BULK
	ASN1F_SNMP_PDU_INFORM
	ASN1F_SNMP_PDU_TRAPv2
	SNMPvarbind
	SNMPget
	SNMPnext
	SNMPresponse
	SNMPset
	SNMPtrapv1
	SNMPbulk
	SNMPinform
	SNMPtrapv2
	SNMP

Scapy layer binding:
====================

bind_layers( Dot3,          LLC,           )
bind_layers( GPRS,          IP,            )
bind_layers( PrismHeader,   Dot11,         )
bind_layers( RadioTap,      Dot11,         )
bind_layers( Dot11,         LLC,           type=2)
bind_layers( PPP,           IP,            proto=33)
bind_layers( Ether,         LLC,           type=122)
bind_layers( Ether,         Dot1Q,         type=33024)
bind_layers( Ether,         Ether,         type=1)
bind_layers( Ether,         ARP,           type=2054)
bind_layers( Ether,         IP,            type=2048)
bind_layers( Ether,         EAPOL,         type=34958)
bind_layers( Ether,         EAPOL,         dst='01:80:c2:00:00:03', type=34958)
bind_layers( Ether,         PPPoED,        type=34915)
bind_layers( Ether,         PPPoE,         type=34916)
bind_layers( CookedLinux,   LLC,           proto=122)
bind_layers( CookedLinux,   Dot1Q,         proto=33024)
bind_layers( CookedLinux,   Ether,         proto=1)
bind_layers( CookedLinux,   ARP,           proto=2054)
bind_layers( CookedLinux,   IP,            proto=2048)
bind_layers( CookedLinux,   EAPOL,         proto=34958)
bind_layers( CookedLinux,   PPPoED,        proto=34915)
bind_layers( CookedLinux,   PPPoE,         proto=34916)
bind_layers( GRE,           LLC,           proto=122)
bind_layers( GRE,           Dot1Q,         proto=33024)
bind_layers( GRE,           Ether,         proto=1)
bind_layers( GRE,           ARP,           proto=2054)
bind_layers( GRE,           IP,            proto=2048)
bind_layers( GRE,           EAPOL,         proto=34958)
bind_layers( PPPoE,         PPP,           code=0)
bind_layers( EAPOL,         EAP,           type=0)
bind_layers( LLC,           STP,           dsap=66, ssap=66, ctrl=3)
bind_layers( LLC,           SNAP,          dsap=170, ssap=170, ctrl=3)
bind_layers( SNAP,          Dot1Q,         code=33024)
bind_layers( SNAP,          Ether,         code=1)
bind_layers( SNAP,          ARP,           code=2054)
bind_layers( SNAP,          IP,            code=2048)
bind_layers( SNAP,          EAPOL,         code=34958)
bind_layers( SNAP,          STP,           code=267)
bind_layers( IPerror,       IPerror,       frag=0, proto=4)
bind_layers( IPerror,       ICMPerror,     frag=0, proto=1)
bind_layers( IPerror,       TCPerror,      frag=0, proto=6)
bind_layers( IPerror,       UDPerror,      frag=0, proto=17)
bind_layers( IP,            IP,            frag=0, proto=4)
bind_layers( IP,            ICMP,          frag=0, proto=1)
bind_layers( IP,            TCP,           frag=0, proto=6)
bind_layers( IP,            UDP,           frag=0, proto=17)
bind_layers( IP,            GRE,           frag=0, proto=47)
bind_layers( UDP,           SNMP,          sport=161)
bind_layers( UDP,           SNMP,          dport=161)
bind_layers( UDP,           MGCP,          dport=2727)
bind_layers( UDP,           MGCP,          sport=2727)
bind_layers( UDP,           DNS,           dport=53)
bind_layers( UDP,           DNS,           sport=53)
bind_layers( UDP,           ISAKMP,        dport=500, sport=500)
bind_layers( UDP,           HSRP,          dport=1985, sport=1985)
bind_layers( UDP,           NTP,           dport=123, sport=123)
bind_layers( UDP,           BOOTP,         dport=67, sport=68)
bind_layers( UDP,           BOOTP,         dport=68, sport=67)
bind_layers( BOOTP,         DHCP,          options='c\x82Sc')
bind_layers( UDP,           RIP,           sport=520)
bind_layers( UDP,           RIP,           dport=520)
bind_layers( RIP,           RIPEntry,      )
bind_layers( RIPEntry,      RIPEntry,      )
bind_layers( Dot11,         Dot11AssoReq,    subtype=0, type=0)
bind_layers( Dot11,         Dot11AssoResp,   subtype=1, type=0)
bind_layers( Dot11,         Dot11ReassoReq,  subtype=2, type=0)
bind_layers( Dot11,         Dot11ReassoResp, subtype=3, type=0)
bind_layers( Dot11,         Dot11ProbeReq,   subtype=4, type=0)
bind_layers( Dot11,         Dot11ProbeResp,  subtype=5, type=0)
bind_layers( Dot11,         Dot11Beacon,     subtype=8, type=0)
bind_layers( Dot11,         Dot11ATIM,       subtype=9, type=0)
bind_layers( Dot11,         Dot11Disas,      subtype=10, type=0)
bind_layers( Dot11,         Dot11Auth,       subtype=11, type=0)
bind_layers( Dot11,         Dot11Deauth,     subtype=12, type=0)
bind_layers( Dot11Beacon,     Dot11Elt,    )
bind_layers( Dot11AssoReq,    Dot11Elt,    )
bind_layers( Dot11AssoResp,   Dot11Elt,    )
bind_layers( Dot11ReassoReq,  Dot11Elt,    )
bind_layers( Dot11ReassoResp, Dot11Elt,    )
bind_layers( Dot11ProbeReq,   Dot11Elt,    )
bind_layers( Dot11ProbeResp,  Dot11Elt,    )
bind_layers( Dot11Auth,       Dot11Elt,    )
bind_layers( Dot11Elt,        Dot11Elt,    )
bind_layers( TCP,           Skinny,        dport=2000)
bind_layers( TCP,           Skinny,        sport=2000)
bind_layers( UDP,           SebekHead,     sport=1101)
bind_layers( UDP,           SebekHead,     dport=1101)
bind_layers( UDP,           SebekHead,     dport=1101, sport=1101)
bind_layers( SebekHead,     SebekV1,       version=1)
bind_layers( SebekHead,     SebekV2Sock,   version=2, type=2)
bind_layers( SebekHead,     SebekV2,       version=2)
bind_layers( SebekHead,     SebekV3Sock,   version=3, type=2)
bind_layers( SebekHead,     SebekV3,       version=3)
bind_layers( CookedLinux,   IrLAPHead,     proto=23)
bind_layers( IrLAPHead,     IrLAPCommand,  Type=1)
bind_layers( IrLAPCommand,  IrLMP,         )
bind_layers( UDP,           NBNSQueryRequest,  dport=137)
bind_layers( UDP,           NBNSRequest,       dport=137)
bind_layers( UDP,           NBNSQueryResponse, sport=137)
bind_layers( UDP,           NBNSQueryResponseNegative, sport=137)
bind_layers( UDP,           NBNSNodeStatusResponse,    sport=137)
bind_layers( NBNSNodeStatusResponse,        NBNSNodeStatusResponseService, )
bind_layers( NBNSNodeStatusResponse,        NBNSNodeStatusResponseService, )
bind_layers( NBNSNodeStatusResponseService, NBNSNodeStatusResponseService, )
bind_layers( NBNSNodeStatusResponseService, NBNSNodeStatusResponseEnd, )
bind_layers( UDP,           NBNSWackResponse, sport=137)
bind_layers( UDP,           NBTDatagram,      dport=138)
bind_layers( TCP,           NBTSession,       dport=139)
bind_layers( NBTSession,                           SMBNegociate_Protocol_Request_Header, )
bind_layers( SMBNegociate_Protocol_Request_Header, SMBNegociate_Protocol_Request_Tail, )
bind_layers( SMBNegociate_Protocol_Request_Tail,   SMBNegociate_Protocol_Request_Tail, )
bind_layers( NBTSession,    SMBNegociate_Protocol_Response_Advanced_Security,  ExtendedSecurity=1)
bind_layers( NBTSession,    SMBNegociate_Protocol_Response_No_Security,        ExtendedSecurity=0, EncryptionKeyLength=8)
bind_layers( NBTSession,    SMBNegociate_Protocol_Response_No_Security_No_Key, ExtendedSecurity=0, EncryptionKeyLength=0)
bind_layers( NBTSession,    SMBSession_Setup_AndX_Request, )
bind_layers( NBTSession,    SMBSession_Setup_AndX_Response, )
bind_layers( HCI_Hdr,       HCI_ACL_Hdr,   type=2)
bind_layers( HCI_Hdr,       Raw,           )
bind_layers( HCI_ACL_Hdr,   L2CAP_Hdr,     )
bind_layers( L2CAP_Hdr,     L2CAP_CmdHdr,      cid=1)
bind_layers( L2CAP_CmdHdr,  L2CAP_CmdRej,      code=1)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConnReq,     code=2)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConnResp,    code=3)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConfReq,     code=4)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConfResp,    code=5)
bind_layers( L2CAP_CmdHdr,  L2CAP_DisconnReq,  code=6)
bind_layers( L2CAP_CmdHdr,  L2CAP_DisconnResp, code=7)
bind_layers( L2CAP_CmdHdr,  L2CAP_InfoReq,     code=10)
bind_layers( L2CAP_CmdHdr,  L2CAP_InfoResp,    code=11)
bind_layers( UDP,           MobileIP,           sport=434)
bind_layers( UDP,           MobileIP,           dport=434)
bind_layers( MobileIP,      MobileIPRRQ,        type=1)
bind_layers( MobileIP,      MobileIPRRP,        type=3)
bind_layers( MobileIP,      MobileIPTunnelData, type=4)
bind_layers( MobileIPTunnelData, IP,           nexthdr=4)
bind_layers( NetflowHeader,   NetflowHeaderV1, version=1)
bind_layers( NetflowHeaderV1, NetflowRecordV1, )

bind_layers(UDP, TFTP, dport=69)
bind_layers(TFTP, TFTP_RRQ, op=1)
bind_layers(TFTP, TFTP_WRQ, op=2)
bind_layers(TFTP, TFTP_DATA, op=3)
bind_layers(TFTP, TFTP_ACK, op=4)
bind_layers(TFTP, TFTP_ERROR, op=5)
bind_layers(TFTP, TFTP_OACK, op=6)
bind_layers(TFTP_RRQ, TFTP_Options)
bind_layers(TFTP_WRQ, TFTP_Options)
bind_layers(TFTP_OACK, TFTP_Options)
=end