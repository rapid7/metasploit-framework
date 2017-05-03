##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'timeout'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'IPID Sequence Scanner',
			'Description' => %q{
				This module will perform an ICMP traceroute over Rex
				L3 pivots. Adapted from rb-traceroute by Jacob Hammack."
			},
			'Author'      => [
				'Jacob Hammack', # Ruby implementation
				'RageLtMan' # MSF Port
				],
			'License'     => MSF_LICENSE
		)

		register_options([
			Opt::RPORT(33434),
			OptBool.new('DNSRVL', [false, 'Perform DNS Reverse Lookup on each IP', false])
		])

		register_advanced_options([
			OptInt.new('MAX_HOPS', [true, "Maximum number of hops to trace through", 30]),
			OptString.new('NS', [
				false,
				"Specify the nameservers to use for queries (default is system DNS), separate by comma"
				]),
			OptBool.new('TCP_DNS', [false, "Run queries over TCP", false])
		])

	end

	def rvl_lookup(hop)
		if datastore['DNSRVL']
			if @res.nil?
				@res = Net::DNS::Resolver.new()
				# The following line requires rex_dns.rb so checking for poxies
				if @res.respond_to?(:proxies)
					@res.proxies=datastore['Proxies'] if datastore['Proxies']
				end
				# Prevent us from using system DNS by default - net/dns pulls OS settings
				@res.nameservers = datastore['NS'].split(/\s|,/) if datastore['NS']
				# If querying over TCP
				if datastore['TCP_DNS']
					vprint_status("Using DNS/TCP")
					@res.use_tcp = true
				end
			end
			query = @res.query(hop)
			resp = []
			query.each_ptr {|p| resp << p}
			return resp.first
		else
			return hop
		end
	end

	def run_host(ip)

		port = datastore['RPORT']
		ttl = 1
		last_addr = nil
		curr_name = Rex::Socket.source_address(ip)
		route_map = Rex::Ui::Text::Table.new({
			'Header' => "Route to #{ip}",
			'Indent' => 1,
			'Columns' => ['TTL', 'IP Address', 'Hostname']
		})

		while ttl < datastore['MAX_HOPS']
			icmp = Socket.new(Socket::AF_INET, Socket::SOCK_RAW, Socket::IPPROTO_ICMP)
			icmp.extend(Rex::Socket::Ip) # Doesnt work for pivoting yet
			icmp.bind(Socket.pack_sockaddr_in(port, ''))

			udp = Rex::Socket::Udp.create
			udp.setsockopt(0, Socket::IP_TTL, ttl)
			udp.connect(Socket.pack_sockaddr_in(port, ip))
			udp.puts ""

			curr_addr = nil

			begin
				# https://en.wikipedia.org/wiki/Time_to_live
				Timeout.timeout(ttl) do
					data, curr_addr = icmp.recvfrom(512)
				end
				break unless curr_addr
				next if curr_addr == last_addr
				last_addr = curr_addr.dup

				curr_name = rvl_lookup(curr_addr)
				route_map << [ttl, curr_addr, curr_name]
				break if curr_addr == ip
			rescue Timeout::Error
				print_error "Timed out at TTL #{ttl}*"
			ensure
				icmp.close
				udp.close
			end

			ttl =+ 1
		end

		if last_addr == ip
			print_good "Reached #{curr_name} at #{ttl} hops"
		else
			print_error "Reached #{ttl} hops, terminating at #{curr_name}"
		end
		vprint_good "\n#{route_map}"

		#Add Report
		report_note(
			:host	=> ip,
			:proto	=> 'ip',
			:type	=> 'traceroute',
			:data	=> route_map.to_csv
		)
	end


end
