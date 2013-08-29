##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Post
	include Msf::Post::Windows::Priv

	def initialize(info={})
		super(update_info(info,
			'Name'            => "Windows Gather Enumerate Domain",
			'Description'     => %q{
				This module identifies the primary domain via the registry. The registry value used is:
				HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\DCName.
				},
			'License'         => MSF_LICENSE,
			'Platform'        => ['win'],
			'SessionTypes'    => ['meterpreter'],
			'Author'          => ['Joshua Abraham <jabra[at]rapid7.com>']
		))
	end

	def reg_getvaldata(key,valname)
		value = nil
		begin
			root_key, base_key = client.sys.registry.splitkey(key)
			open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ)
			v = open_key.query_value(valname)
			value = v.data
			open_key.close
		rescue
		end
		return value
	end

	def get_domain()
		domain = nil
		begin
			subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
			v_name = "DCName"
			domain = reg_getvaldata(subkey, v_name)
		rescue
			print_error("This host is not part of a domain.")
		end
		return domain
	end

	def gethost(hostname)
		hostip = nil
		if client.platform =~ /^x64/
			size = 64
			addrinfoinmem = 32
		else
			size = 32
			addrinfoinmem = 24
		end

		## get IP for host
		begin
			vprint_status("Looking up IP for #{hostname}")
			result = client.railgun.ws2_32.getaddrinfo(hostname, nil, nil, 4 )
			if result['GetLastError'] == 11001
				return nil
			end
			addrinfo = client.railgun.memread( result['ppResult'], size )
			ai_addr_pointer = addrinfo[addrinfoinmem,4].unpack('L').first
			sockaddr = client.railgun.memread( ai_addr_pointer, size/2 )
			ip = sockaddr[4,4].unpack('N').first
			hostip = Rex::Socket.addr_itoa(ip)
		rescue ::Exception => e
			print_error(e)
		end
		return hostip
	end

	def run
		domain = get_domain()
		if not domain.nil? and domain =~ /\./
			dom_info =  domain.split('.')
			dom_info[0].sub!(/\\\\/,'')
			report_note(
				:host   => session,
				:type   => 'windows.domain',
				:data   => { :domain => dom_info[1] },
				:update => :unique_data
			)
			print_good("FOUND Domain: #{dom_info[1]}")
			dc_ip = gethost(dom_info[0])
			if not dc_ip.nil?
				print_good("FOUND Domain Controller: #{dom_info[0]} (IP: #{dc_ip})")
				report_host({
						:host => dc_ip,
						:name => dom_info[0],
						:info => "Domain controller for #{dom_info[1]}"
					})
			else
				print_good("FOUND Domain Controller: #{dom_info[0]}")
			end
		end
	end
end
