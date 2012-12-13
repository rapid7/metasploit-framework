# -*- coding: binary -*-s

require 'rex/socket'
require 'rex/proto/dhcp'

module Rex
module Proto
module DHCP

##
#
# DHCP Server class
# not completely configurable - written specifically to grab PXEBoot responses
# - Meatballs - Heavily based upon scriptjunkie's DHCP Server!
##

class Client

	include Rex::Socket

	def initialize(opts, context = {})
		self.listen_port = 68 # mandatory (bootpc)
		self.context = context
		self.sock = nil

		source = Rex::Socket.source_address
		self.ipstring = Rex::Socket.addr_aton(source)
	end

	# Start the DHCP listener
	def start(listen_host='0.0.0.0')
		self.responses = []

		self.sock = Rex::Socket::Udp.create(
			'LocalHost' => listen_host,
			'LocalPort' => listen_port,
			'Context'   => context
		)

		self.thread = Rex::ThreadFactory.spawn("DHCPClientMonitor", false) {
			monitor_socket
		}
	end

	# Stop the DHCP listener
	def stop
		self.thread.kill
		self.served = {}
		self.sock.close rescue nil
	end

	def report(&block)
		self.reporter = block
	end

	def create_discover(chaddr) # VMWare Mac
		pkt =  [Request].pack('C')
		pkt << [1].pack('C') # hwtype
		pkt << [6].pack('C') # hwlen
		pkt << [0].pack('C')
		pkt << [0].pack('N') # transaction id
		pkt << [0].pack('n') # seconds
		pkt << [0].pack('n') # flags
		pkt << Rex::Socket.addr_aton("0.0.0.0") # ciaddr
		pkt << Rex::Socket.addr_aton("0.0.0.0") # yiaddr
		pkt << Rex::Socket.addr_aton("0.0.0.0") # siaddr
		pkt << Rex::Socket.addr_aton("0.0.0.0") # giaddr
		pkt << chaddr + "\x00"*10 # client mac + padding
		pkt << "\x00"*64 # sname
		pkt << "\x00"*128 # file
		pkt << DHCPMagic
		pkt << dhcpoption(OpMessageType, [DHCPDiscover].pack('C'))
		pkt << dhcpoption(OpParamReqList, "\x01\x02\x03\x05\x06\x0b\x0c\x0d\x0f\x10\x11\x12\x2b\x36\x3c\x43\x80\x81\x82\x83\x84\x85\x86\x87")
		pkt << dhcpoption(OpVendorClassID, "PXEClient:Arch:00000:UNDI:002001")
		pkt << dhcpoption(OpEnd)
		return pkt
	end

	def create_request(chaddr, ciaddr)
		pkt =  [Request].pack('C')
		pkt << [1].pack('C') # hwtype
		pkt << [6].pack('C') # hwlen
		pkt << [0].pack('C')
		pkt << [0].pack('N') # transaction id
		pkt << [0].pack('n') # seconds
		pkt << [0].pack('n') # flags
		pkt << Rex::Socket.addr_aton(ciaddr) # ciaddr
		pkt << Rex::Socket.addr_aton("0.0.0.0") # yiaddr
		pkt << Rex::Socket.addr_aton("0.0.0.0") # siaddr
		pkt << Rex::Socket.addr_aton("0.0.0.0") # giaddr
		pkt << chaddr + "\x00"*10 # client mac + padding
		pkt << "\x00"*64 # sname
		pkt << "\x00"*128 # file
		pkt << DHCPMagic
		pkt << dhcpoption(OpMessageType, [DHCPRequest].pack('C'))
		pkt << dhcpoption(OpParamReqList, "\x01\x02\x03\x05\x06\x0b\x0c\x0d\x0f\x10\x11\x12\x2b\x36\x3c\x43\x80\x81\x82\x83\x84\x85\x86\x87")
		pkt << dhcpoption(OpVendorClassID, "PXEClient:Arch:00000:UNDI:002001")
		pkt << dhcpoption(OpEnd)
		return pkt
	end



	# Send a single packet to the specified host
	def send_packet(ip, pkt, port=67)
		if ip
			self.sock.sendto( pkt, ip, port )
		else
			if not self.sock.sendto( pkt, '255.255.255.255', port )
				self.sock.sendto( pkt, self.broadcasta, port )
			end
		end
	end

	attr_accessor :sock, :served, :reporter, :responses, :thread, :listen_port, :context, :ipstring


protected

	# See if there is anything to do.. If so, dispatch it.
	def monitor_socket
		while true
			rds = [@sock]
			wds = []
			eds = [@sock]

			r,w,e = ::IO.select(rds,wds,eds,1)

			if (r != nil and r[0] == self.sock)
				buf,host,port = self.sock.recvfrom(65535)
				# Lame compatabilitiy :-/
				from = [host, port]
				response = parse_response(from, buf)
				self.reporter.call(response)
				self.responses << response
			end

		end
	end

	def dhcpoption(type, val = nil)
		ret = ''
		ret << [type].pack('C')

		if val
			ret << [val.length].pack('C') + val
		end

		ret
	end

	# Dispatch a packet that we received
	def parse_response(from, buf)
		hwlen = buf[2].unpack('C').first
		response = {
			:from			=> from,
			:type	 		=> buf[0].unpack('C').first,
			:hwtype 		=> buf[1].unpack('C').first,
			:hwlen 			=> hwlen,
			:hops			=> buf[3].unpack('C').first,
			:txid	 		=> buf[4..7].unpack('N').first,
			:elapsed	 	=> buf[8..9].unpack('n').first,
			:flags			=> buf[10..11].unpack('n').first,
			:clientip 		=> buf[12..15].unpack('C*').join('.'),
			:yiaddr 		=> buf[16..19].unpack('C*').join('.'),
			:nextip 		=> buf[20..23].unpack('C*').join('.'),
			:relayip	 	=> buf[24..27].unpack('C*').join('.'),
			:clienthwaddr	 	=> buf[28..(27+hwlen)].unpack('H2H2H2H2').join(':'),
			:servhostname	 	=> buf[44..107],
			:filename 		=> buf[108..235],
			:magic			=> buf[236..239]
		}

		dhcp_options = []

		# options parsing loop
		spot = 240
		while (spot < buf.length - 3)
			optionType = buf[spot,1].unpack("C").first
			break if optionType == 0xff

			optionLen = buf[spot + 1,1].unpack("C").first
			optionValue = buf[(spot + 2)..(spot + optionLen + 1)]
			spot = spot + optionLen + 2

			case optionType
			when OpMessageType
				optionValue = optionValue.unpack("C").first
			when OpDHCPServer
				optionValue = Rex::Socket.addr_ntoa(optionValue)
			end

			dhcp_options << {:opt => optionType, :val => optionValue}
		end

		response.merge!(:dhcp_opts => dhcp_options)
		return response
	end

	def is_pxe_response(response)
	end
end

end
end
end
