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
		self.listen_port = 67 # mandatory (bootps)
		self.context = context
		self.sock = nil

		@shutting_down = false

		self.myfilename = hash['FILENAME'] || ""
		self.myfilename << ("\x00" * (128 - self.myfilename.length))

		source = hash['SRVHOST'] || Rex::Socket.source_address
		self.ipstring = Rex::Socket.addr_aton(source)

		ipstart = hash['DHCPIPSTART']
		if ipstart
			self.start_ip = Rex::Socket.addr_atoi(ipstart)
		else
			self.start_ip = "#{self.ipstring[0..2]}\x20" #default range x.x.x.32-254
		end
		self.current_ip = start_ip

		ipend = hash['DHCPIPEND']
		if ipend
			self.end_ip = Rex::Socket.addr_atoi(ipend)
		else
			self.end_ip = "#{self.ipstring[0..2]}\xfe"
		end

		# netmask
		netmask = hash['NETMASK'] || "255.255.255.0"
		self.netmaskn = Rex::Socket.addr_aton(netmask)

		# router
		router = hash['ROUTER'] || source
		self.router = Rex::Socket.addr_aton(router)

		# dns
		dnsserv = hash['DNSSERVER'] || source
		self.dnsserv = Rex::Socket.addr_aton(dnsserv)

		# broadcast
		if hash['BROADCAST']
			self.broadcasta = Rex::Socket.addr_aton(hash['BROADCAST'])
		else
			self.broadcasta = Rex::Socket.addr_itoa( self.start_ip | (Rex::Socket.addr_ntoi(self.netmaskn) ^ 0xffffffff) )
		end

		self.served = {}
		if (hash['SERVEONCE'])
			self.serveOnce = true
		else
			self.serveOnce = false
		end
		
		if (hash['PXE'])
			self.servePXE = true
		else
			self.servePXE = false
		end
		
		self.leasetime = 600
		self.relayip = "\x00\x00\x00\x00" # relay ip - not currently suported
		self.pxeconfigfile = "update2"
		self.pxepathprefix = ""
		self.pxereboottime = 2000
	end


	# Start the DHCP server
	def start
		self.sock = Rex::Socket::Udp.create(
			'LocalHost' => listen_host,
			'LocalPort' => listen_port,
			'Context'   => context
		)

		self.thread = Thread.new {
			monitor_socket
		}
	end

	# Stop the DHCP server
	def stop
		@shutting_down = true
		self.thread.kill
		self.sock.close rescue nil
	end


	# Set an option
	def set_option(opts)
		allowed_options = [
			:serveOnce, :servePXE, :relayip, :leasetime, :dnsserv,
			:pxeconfigfile, :pxepathprefix, :pxereboottime, :router
		]

		opts.each_pair { |k,v|
			next if not v
			if allowed_options.include?(k)
				self.instance_variable_set("@#{k}", v)
			end
		}
	end


	# Send a single packet to the specified host
	def send_packet(ip, pkt)
		port = 68 # bootpc
		if ip
			self.sock.sendto( pkt, ip, port )
		else
			if not self.sock.sendto( pkt, '255.255.255.255', port )
				self.sock.sendto( pkt, self.broadcasta, port )
			end
		end
	end

	attr_accessor :listen_host, :listen_port, :context, :leasetime, :relayip, :router, :dnsserv
	attr_accessor :sock, :thread, :myfilename, :ipstring, :served, :serveOnce
	attr_accessor :current_ip, :start_ip, :end_ip, :broadcasta, :netmaskn
	attr_accessor :servePXE, :pxeconfigfile, :pxepathprefix, :pxereboottime

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

	def dhcpoption(type, val = nil)
		ret = ''
		ret << [type].pack('C')

		if val
			ret << [val.length].pack('C') + val
		end

		ret
	end

	# Dispatch a packet that we received
	def dispatch_request(from, buf)
		type = buf.unpack('C').first
		if (type != Request)
			#dlog("Unknown DHCP request type: #{type}")
			return
		end

		# parse out the members
		hwtype = buf[1,1]
		hwlen = buf[2,1].unpack("C").first
		hops = buf[3,1]
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

		if (magic != DHCPMagic)
			#dlog("Invalid DHCP request - bad magic.")
			return
		end

		messageType = 0
		pxeclient = false

		# options parsing loop
		spot = 240
		while (spot < buf.length - 3 && buf[spot] != 0xff)
			optionType = buf[spot,1].unpack("C").first
			optionLen = buf[spot + 1,1].unpack("C").first
			optionValue = buf[(spot + 2)..(spot + optionLen + 1)]
			spot = spot + optionLen + 2
			if optionType == 53
				messageType = optionValue.unpack("C").first
			elsif optionType == 150
				pxeclient = true
			end
		end

		if pxeclient == false && self.servePXE == true
			#dlog ("No tftp server request; ignoring (probably not PXE client)")
			return
		end

		# prepare response
		pkt = [Response].pack('C')
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
		pkt << self.relayip
		pkt << buf[28..43] #client hw address
		pkt << servhostname
		pkt << self.myfilename
		pkt << magic
		pkt << "\x35\x01" #Option

		if messageType == DHCPDiscover  #DHCP Discover - send DHCP Offer
			pkt << [DHCPOffer].pack('C')
			# check if already served based on hw addr (MAC address)
			if self.serveOnce == true && self.served.has_key?(buf[28..43])
				#dlog ("Already served; allowing normal boot")
				return
			end
		elsif messageType == DHCPRequest #DHCP Request - send DHCP ACK
			pkt << [DHCPAck].pack('C')
			# now we ignore their discovers (but we'll respond to requests in case a packet was lost)
			self.served.merge!( buf[28..43] => true ) 
		else
			#dlog("ignoring unknown DHCP request - type #{messageType}")
			return
		end

		# Options!
		pkt << dhcpoption(OpDHCPServer, self.ipstring)
		pkt << dhcpoption(OpLeaseTime, [self.leasetime].pack('N'))
		pkt << dhcpoption(OpSubnetMask, self.netmaskn)
		pkt << dhcpoption(OpRouter, self.router)
		pkt << dhcpoption(OpDns, self.dnsserv)
		pkt << dhcpoption(OpPXEMagic, PXEMagic)
		pkt << dhcpoption(OpPXEConfigFile, self.pxeconfigfile)
		pkt << dhcpoption(OpPXEPathPrefix, self.pxepathprefix)
		pkt << dhcpoption(OpPXERebootTime, [self.pxereboottime].pack('N'))
		pkt << dhcpoption(OpEnd)

		pkt << ("\x00" * 32) #padding

		send_packet(nil, pkt)
	end

end

end
end
end
