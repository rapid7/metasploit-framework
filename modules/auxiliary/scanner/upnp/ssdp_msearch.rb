##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'SSDP M-SEARCH Gateway Information Discovery',
			'Version'     => '$Revision$',
			'Description' => 'Discover information about the local gateway via UPnP',
			'Author'      => 'todb',
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::CHOST,
				Opt::RPORT(1900),
				Opt::RHOST("239.255.255.250"), # Generally don't change this.
				OptPort.new('SRVPORT', [ false, "The source port to listen for replies.", 0]),
			], self.class
		)

		@result = []
	end

	def upnp_client_listener()
		sock = Rex::Socket::Udp.create(
			'LocalHost' => datastore['CHOST'] || nil,
			'LocalPort' => @sport,
			'Context' => {'Msf' => framework, 'MsfExploit' => self}
		)
		add_socket(sock)
		while (r = sock.recvfrom(65535, 5) and r[1])
			@result << r
		end
	end

	def set_server_port
		if datastore['SRVPORT'].to_i.zero?
			datastore['SRVPORT'] = rand(10_000) + 40_000
		else
			datastore['SRVPORT'].to_i
		end
	end

	def rport
		datastore['RPORT'].to_i
	end

	def rhost
		datastore['RHOST']
	end

	def target
		"%s:%d" % [rhost, rport]
	end

	# The problem is, the response comes from someplace we're not
	# expecting, since we're sending out on the multicast address.
	# This means we need to listen on our sending port, either with
	# packet craftiness or by being able to set our sport.
	def run

		print_status("#{target}: Sending SSDP M-SEARCH Probe.")
		@result = []

		@sport = set_server_port

		begin
			udp_send_sock = nil

			server_thread = framework.threads.spawn("Module(#{self.refname})-Listener", false) { upnp_client_listener }

			# TODO: Test to see if this scheme will work when pivoted.

			# Create an unbound UDP socket if no CHOST is specified, otherwise
			# create a UDP socket bound to CHOST (in order to avail of pivoting)
			udp_send_sock = Rex::Socket::Udp.create(
				'LocalHost' => datastore['CHOST'] || nil,
				'LocalPort' => @sport,
				'Context' => {'Msf' => framework, 'MsfExploit' => self}
			)
			add_socket(udp_send_sock)
			data = create_msearch_packet(rhost,rport)
			begin
				udp_send_sock.sendto(data, rhost, rport, 0)
			rescue ::Interrupt
				raise $!
			rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
				nil
			end

			begin
				Timeout.timeout(6) do
					while @result.size.zero?
						select(nil, nil, nil, 0.25)
						parse_reply @result
					end
				end
			rescue Timeout::Error
			end
		end
	end

	# Someday, take all these very similiar parse_reply functions
	# and make them proper block consumers.
	def parse_reply(pkts)
		pkts.each do |pkt|
			# Ignore "empty" packets
			return if not pkt[1]

			addr = pkt[1]
			if(addr =~ /^::ffff:/)
				addr = addr.sub(/^::ffff:/, '')
			end

			port = pkt[2]

			data = pkt[0]
			info = []
			if data =~ /^Server:[\s]*(.*)/
				server_string = $1
				info << "\"#{server_string.to_s.strip}\""
			end

			ssdp_host = nil
			ssdp_port = 80
			if data =~ /^Location:[\s]*(.*)/
				location_string = $1
				info << location_string.to_s.strip
				if location_string[/(https?):\x2f\x2f([^\x5c\x2f]+)/]
					ssdp_host,ssdp_port = $2.split(":") if $2.respond_to?(:split)
					if ssdp_port.nil?
						ssdp_port = ($1 == "http" ? 80 : 443)
					end
				end
			end

			if data =~ /^USN:[\s]*(.*)/
				usn_string = $1
				info << usn_string.to_s.strip
			end

			report_service(
				:host  => addr,
				:port  => port,
				:proto => 'udp',
				:name  => 'ssdp',
				:info  => info.join("|")
			)
			if info.first.nil? || info.first.empty?
				print_status "#{addr}:#{port}: Got an incomplete response."
			else
				print_good "#{addr}:#{port}: Got an SSDP response from #{info.first}"
			end

			if ssdp_host
				report_service(
					:host  => ssdp_host,
					:port  => ssdp_port,
					:proto => 'tcp',
					:name  => 'upnp',
					:info  => location_string
				)
				print_good "#{ssdp_host}:#{ssdp_port}: UPnP services advertised at #{info.grep(/#{ssdp_host}/).first}"
			end
		end
	end

	# I'm sure this could be a million times cooler.
	def create_msearch_packet(host,port)
		data = "M-SEARCH * HTTP/1.1\r\n"
		data << "Host:#{host}:#{port}\r\n"
		data << "ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
		data << "Man:\"ssdp:discover\"\r\n"
		data << "MX:3\r\n"
		return data
	end

end
