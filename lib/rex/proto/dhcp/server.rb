# $Id$

require 'rex/socket'
require 'rex/proto/dhcp'

module Rex
module Proto
module DHCP

##
#
# DHCP Server class
# not completely configurable - written specifically for a PXE server
# - scriptjunkie
##

class Server

	include Rex::Socket

	def initialize(hash, context = {})
		self.listen_host = '0.0.0.0' # clients don't already have addresses. Needs to be 0.0.0.0
		self.listen_port = 67 # mandatory
		self.context = context
		self.sock = nil

		@shutting_down = false

		self.myfilename = hash['FILENAME'] || ""
		self.myfilename << ("\x00" * (128 - self.myfilename.length))

		source = hash['SRVHOST'] || Rex::Socket.source_address
		self.ipstring = Rex::Socket.addr_aton(source)

		first_ip = hash['DHCPIPSTART'] || "#{self.ipstring[0..2]}\x20" #??
		self.start_ip = Rex::Socket.addr_atoi(first_ip)

		self.current_ip = start_ip
		hash['DHCPIPEND'] || "#{self.ipstring[0..2]}\xfe"
		self.end_ip = Rex::Socket.addr_atoi(last_ip)

		# netmask
		netmask = hash['NETMASK'] || "255.255.255.0"
		self.netmaskn = Rex::Socket.addr_aton(netmask)

		self.broadcasta = Rex::Socket.addr_itoa( self.start_ip | (Rex::Socket.addr_ntoi(self.netmaskn) ^ 0xffffffff) )

		self.served = {}
		if (hash['SERVEONCE'])
			self.serveOnce = true
		else
			self.serveOnce = false
		end
	end

	# Start the DHCP server
	def start
		self.sock = Rex::Socket::Udp.create(
			'LocalHost' => listen_host,
			'LocalPort' => listen_port,
			'Context'   => context,
			'IPv6' => false
		)

		self.thread = Thread.new {
			monitor_socket
		}
	end

	# Stop the DHCP server
	def stop
		@shutting_down = true
		self.thread.kill
		self.sock.close
	end

	# Send a single packet to the specified host
	def send_packet(from, pkt)
		# should be broadcast, but that fails  ...(pkt, "255.255.255.255", from[1])
		self.sock.sendto( pkt, self.broadcasta, from[1])
		#send( pkt, 0, Rex::Socket.to_sockaddr(0xffffffff, from[1]))
	end

	attr_accessor :listen_host, :listen_port, :context
	attr_accessor :sock, :thread, :myfilename, :ipstring, :served, :serveOnce
	attr_accessor :current_ip, :start_ip, :end_ip, :broadcasta, :netmaskn


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
				dispatch_request(from, buf)
			end

		end
	end

	def dhcpoption(type,val)
		return type+[val.length].pack("C")+val
	end

	# Dispatch a packet that we received
	def dispatch_request(from, buf)
		type = buf[0]
		if (type != "\x01")
			#dlog("Unknown DHCP request type: #{type}")
			return
		end

		# parse out the members
		hwtype = buf[1]
		hwlen = buf[2].unpack("C")[0]
		hops = buf[3]
		txid = buf[4..7]
		elapsed = buf[8..9]
		flags = buf[10..11]
		clientip = buf[12..15]
		givenip = buf[16..19]
		nextip = buf[20..23]
		relayip = buf[24..27]
		clienthwaddr = buf[28..(27+hwlen)]
		servhostname = buf[44..107]
		filename = buf[108..235]
		magic = buf[236..239]

		if (magic != "\x63\x82\x53\x63")
			#dlog("Invalid DHCP request - bad magic.")
			return
		end

		messageType = 0
		pxeclient = false

		# options parsing loop
		spot = 240
		while (spot < buf.length - 3 && buf[spot] != 0xff)
			optionType = buf[spot].unpack("C")[0]
			optionLen = buf[spot + 1].unpack("C")[0]
			optionValue = buf[(spot + 2)..(spot + optionLen + 1)]
			spot = spot + optionLen + 2
			if optionType == 53
				messageType = optionValue.unpack("C")[0]
			elsif optionType == 150
				pxeclient = true
			end
		end
		if pxeclient == false
			#dlog ("No tftp server request; ignoring (probably not PXE client)")
			return
		end

		# prepare response
		pkt = "\x02"
		pkt << buf[1..7] #hwtype, hwlen, hops, txid
		pkt << "\x00\x00\x00\x00"  #elapsed, flags
		pkt << clientip

		# give next ip address (not super reliable high volume but it should work for a basic server)
		self.current_ip += 1
		if self.current_ip > self.end_ip
			self.current_ip = self.start_ip
		end
		pkt << Rex::Socket.addr_iton(self.current_ip)
		pkt << self.ipstring #next server ip
		pkt << "\x00\x00\x00\x00" #relay ip - not currently supported
		pkt << buf[28..43] #client hw address
		pkt << servhostname
		pkt << self.myfilename
		pkt << magic
		pkt << "\x35\x01" #Option
		if messageType == 1  #DHCP Discover - send DHCP Offer
			pkt << "\x02"
			# check if already served based on hw addr (MAC address)
			if self.serveOnce == true && self.served[buf[28..43]]
				#dlog ("Already served; allowing normal boot")
				return
			end
		elsif messageType == 3 #DHCP Request - send DHCP ACK
			pkt << "\x05"
			self.served[buf[28..43]] = true  #now we ignore their discovers (but we'll respond to requests in case a packet was lost)
		else
			#dlog("ignoring unknown DHCP request - type #{messageType}")
			return
		end
		pkt << dhcpoption("\x36",self.ipstring) #Option DHCP server
		pkt << dhcpoption("\x33","\x00\x00\x02\x58") #Option Lease Time - 10 minutes
		pkt << dhcpoption("\x01",self.netmaskn) #Subnet mask
		pkt << dhcpoption("\x03",self.ipstring) #Option router
		pkt << dhcpoption("\xD0","\xF1\x00\x74\x7E") #pxelinux.magic
		pkt << dhcpoption("\xD1","update2") #pxelinux.configfile
		pkt << dhcpoption("\xD2","") #pxelinux.pathprefix
		pkt << dhcpoption("\xD3",[20].pack("N")) #pxelinux.reboottime
		pkt << "\xff" # end option
		pkt << ("\x00" * 32) #padding
		send_packet(from, pkt)
	end

end

end
end
end
