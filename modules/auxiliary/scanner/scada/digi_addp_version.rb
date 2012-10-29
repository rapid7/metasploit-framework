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
require 'rex/proto/addp'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Digi ADDP Information Discovery',
			'Version'     => '$Revision$',
			'Description' => 'Discover host information through the Digi International ADDP service',
			'Author'      => 'hdm',
			'References'  => 
				[
					['URL', 'http://qbeukes.blogspot.com/2009/11/advanced-digi-discovery-protocol_21.html'],
					['URL', 'http://www.digi.com/wiki/developer/index.php/Advanced_Device_Discovery_Protocol_%28ADDP%29'],
				],
			'License'     => MSF_LICENSE
		)

		register_options(
		[
		Opt::CHOST,
			OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
			Opt::RPORT(2362)
		], self.class)
	end


	# Define our batch size
	def run_batch_size
		datastore['BATCHSIZE'].to_i
	end

	def rport
		datastore['RPORT'].to_i
	end

	# Fingerprint a single host
	def run_batch(batch)

		print_status("Sending Digi ADDP probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")

		@results = {}
		begin
			udp_sock = nil
			idx = 0

			# Create an unbound UDP socket if no CHOST is specified, otherwise
			# create a UDP socket bound to CHOST (in order to avail of pivoting)
			udp_sock = Rex::Socket::Udp.create( { 'LocalHost' => datastore['CHOST'] || nil, 'Context' => {'Msf' => framework, 'MsfExploit' => self} })
			add_socket(udp_sock)

			batch.each do |ip|
				begin

					# Try all currently-known magic probe values
					Rex::Proto::ADDP.request_config_all.each do |pkt|
						udp_sock.sendto(pkt, ip, rport, 0)
					end

				rescue ::Interrupt
					raise $!
				rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
					nil
				end

				if (idx % 30 == 0)
					while (r = udp_sock.recvfrom(65535, 0.1) and r[1])
						parse_reply(r)
					end
				end

				idx += 1
			end

			while (r = udp_sock.recvfrom(65535, 3) and r[1])
				parse_reply(r)
			end

		rescue ::Interrupt
			raise $!
		rescue ::Errno::ENOBUFS
			print_status("Socket buffers are full, waiting for them to flush...")
			while (r = udp_sock.recvfrom(65535, 0.1) and r[1])
				parse_reply(r)
			end
			select(nil, nil, nil, 0.25)
		rescue ::Exception => e
			print_error("Unknown error: #{e.class} #{e} #{e.backtrace}")
		end
	end


	def parse_reply(pkt)
		# Ignore "empty" packets
		return if not pkt[1]

		addr = pkt[1]
		if(addr =~ /^::ffff:/)
			addr = addr.sub(/^::ffff:/, '')
		end

		data = pkt[0]

		@results[addr] ||= {}
		@results[addr] = Rex::Proto::ADDP.decode_reply(data)
		
		return unless @results[addr][:magic] and @results[addr][:mac]

		inf = Rex::Proto::ADDP.reply_to_string(@results[addr])

		if inside_workspace_boundary?(addr)
			report_service(
				:host  => addr,
				:mac   => @results[addr][:mac],
				:port  => pkt[2],
				:proto => 'udp',
				:name  => 'addp',
				:info  => inf
			)
		end
		print_status("#{addr}:#{pkt[2]} #{inf}")
	end


end
