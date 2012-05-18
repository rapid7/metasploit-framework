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
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'pcAnywhere UDP Service Discovery',
			'Version'     => '$Revision$',
			'Description' => 'Discover active pcAnywhere services through UDP',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE,
			'References'  =>
				[
					['URL', 'http://www.unixwiz.net/tools/pcascan.txt']
				]
		)

		register_options(
		[
			Opt::CHOST,
			OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
			Opt::RPORT(5632)
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

		print_status("Sending pcAnywhere discovery requests to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")

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
					# Send network query
					udp_sock.sendto("NQ", ip, rport, 0)

					# Send status query
					udp_sock.sendto("ST", ip, rport, 0)
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

		@results.keys.each do |ip|
			next unless inside_workspace_boundary?(ip)
			data = @results[ip]

			info = ""

			if data[:name]
				info << "Name: #{data[:name]} "
			end

			if data[:stat]
				info << "- #{data[:stat]} "
			end

			if data[:caps]
				info << "( #{data[:caps]} ) "
			end

			report_service(:host => ip, :port => rport, :proto => 'udp', :name => "pcanywhere_stat", :info => info)
			report_note(:host => ip, :port => rport, :proto => 'udp', :name => "pcanywhere_stat", :update => :unique, :ntype => "pcanywhere.status", :data => data )
			print_status("#{ip}:#{rport} #{info}")
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

		case data
		when /^NR(........................)(........)/

			name = $1.dup
			caps = $2.dup

			name = name.gsub(/_+$/, '').gsub("\x00", '').strip
			caps = caps.gsub(/_+$/, '').gsub("\x00", '').strip

			@results[addr] ||= {}
			@results[addr][:name] = name
			@results[addr][:caps] = caps

		when /^ST(.+)/
			@results[addr] ||= {}
			buff = $1.dup
			stat = 'Unknown'

			if buff[2,1].unpack("C")[0] == 67
				stat = "Available"
			end

			if buff[2,1].unpack("C")[0] == 11
				stat = "Busy"
			end

			@results[addr][:stat] = stat
		else
			print_error("#{addr} Unknown: #{data.inspect}")
		end

	end

end
