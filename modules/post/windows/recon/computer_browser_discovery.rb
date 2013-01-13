
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Recon Computer Browser Discovery',
				'Description'   => %q{ This module uses railgun to discover hostnames and IPs on the network.
					LTYPE should be set to one of the following values: WK (all workstations), SVR (all servers),
					SQL (all SQL servers), DC (all Domain Controllers), DCBKUP (all Domain Backup Servers),
					NOVELL (all Novell servers), PRINTSVR (all Print Que servers), MASTERBROWSER (all Master Browswers),
					WINDOWS (all Windows hosts), or UNIX (all Unix hosts).
					},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'mubix' ],
				'Platform'      => [ 'win' ],
				'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptString.new('LTYPE',  [true, 'Account informations (type info for known types)', 'WK']), # Enum would be a better choice
				OptString.new('DOMAIN', [false, 'Domain to perform lookups on, default is current domain',nil]),
				OptBool.new('SAVEHOSTS', [true, 'Save Discovered Hosts to the Database', false])
			], self.class)
	end

	def parse_netserverenum(startmem,count)
		base = 0
		sys_list = []
		mem = client.railgun.memread(startmem, 24*count)

		count.times{|i|
			x = {}
			x[:platform_id] = mem[(base + 0),4].unpack("V*")[0]
			cnameptr = mem[(base + 4),4].unpack("V*")[0]
			x[:major_ver] = mem[(base + 8),4].unpack("V*")[0]
			x[:minor_ver] = mem[(base + 12),4].unpack("V*")[0]
			x[:type] = mem[(base + 16),4].unpack("V*")[0]
			commentptr = mem[(base + 20),4].unpack("V*")[0]

			x[:cname] = client.railgun.memread(cnameptr,27).split("\0\0")[0].split("\0").join
			x[:comment] = client.railgun.memread(commentptr,255).split("\0\0")[0].split("\0").join
			sys_list << x
			base = base + 24
			vprint_status("Identified: #{x[:cname]} - #{x[:comment]}")
		}
		return sys_list
	end

	def run
		### MAIN ###
		client = session

		domain = nil

		# Default = SV_TYPE_NT
		# Servers = SV_TYPE_ALL
		# Workstations = SV_TYPE_WORKSTATION
		# Domain Controllers = SV_TYPE_DOMAINCTRL
		# Novell Server = SV_TYPE_NOVELL
		# Terminal Servers = SV_TYPE_TERMINALSERVER
		# SQL Servers = SV_TYPE_SQLSERVER
		lookuptype = 1

		case datastore['LTYPE']
			when 'WK' then lookuptype = "1".hex
			when 'SVR' then lookuptype = "2".hex
			when 'SQL' then lookuptype = "4".hex
			when 'DC' then lookuptype = "8".hex
			when 'DCBKUP' then lookuptype = "10".hex
			when 'TIME' then lookuptype = "20".hex
			when 'NOVELL' then lookuptype = "80".hex
			when 'PRINTSVR' then lookuptype = "200".hex
			when 'MASTERBROWSER' then lookuptype = "40000".hex
			when 'WINDOWS' then lookuptype = "400000".hex
			when 'UNIX' then lookuptype = "800".hex
			when 'LOCAL' then lookuptype = "40000000".hex
		end

		if client.platform =~ /^x64/
			nameiterator = 8
			size = 64
			addrinfoinmem = 32
		else
			nameiterator = 4
			size = 32
			addrinfoinmem = 24
		end

		result = client.railgun.netapi32.NetServerEnum(nil,101,4,-1,4,4,lookuptype,datastore['DOMAIN'],0)
		# print_error(result.inspect)
		if result['totalentries'] == 0
			print_error("No systems found of that type")
			return
		end
		print_status("Found #{result['totalentries']} systems.")

		endofline = 0
		i = nameiterator
		netview = parse_netserverenum(result['bufptr'],result['totalentries'])


		## get IP for host
		begin
			netview.each do |x|
				vprint_status("Looking up IP for #{x[:cname]}")
				print '.'
				result = client.railgun.ws2_32.getaddrinfo(x[:cname], nil, nil, 4 )
				if result['GetLastError'] == 11001
					print_error("There was an error resolving the IP for #{x[:cname]}")
					next
				end
				addrinfo = client.railgun.memread( result['ppResult'], size )
				ai_addr_pointer = addrinfo[addrinfoinmem,4].unpack('L').first
				sockaddr = client.railgun.memread( ai_addr_pointer, size/2 )
				ip = sockaddr[4,4].unpack('N').first
				x[:ip] = Rex::Socket.addr_itoa(ip)
				x[:ip] = '' unless x[:ip]
			end
		rescue ::Exception => e
			print_error(e)
			print_status('Windows 2000 and prior does not support getaddrinfo')
		end

		netview = netview.sort_by {|e| e[:type]}

		results = Rex::Ui::Text::Table.new(
			'Header' => 'Netdiscovery Results',
			'Indent' => 2,
			'Columns' => ['TYPE', 'IP', 'COMPUTER NAME', 'VERSION', 'COMMENT']
		)

		netview.each do |x|
			results << [x[:type], x[:ip], x[:cname], "#{x[:major_ver]}.#{x[:minor_ver]}", x[:comment]]
			report_host(:host => x[:ip]) if datastore['SAVEHOSTS'] and !(x[:ip].empty?)
		end
		print_status(results.to_s)
		store_loot("discovered.hosts", "text/plain", session, results.to_s, "discovered_hosts.txt", "Computer Browser Discovered Hosts")

		print_status('If none of the IP addresses show up you are running this from a Win2k or older system')
		print_status("If a host doesn't have an IP it either timed out or only has an IPv6 address assinged to it")
	end
end
