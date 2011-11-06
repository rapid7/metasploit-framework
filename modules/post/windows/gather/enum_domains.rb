##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Domain Enumeration',
			'Description'   => %q{
				This module enumerates currently the domains a host can see and the domain
				controllers for that domain. 
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Rob Fuller <mubix[at]hak5.org>'],
			'Version'       => '$Revision$',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
	end

	def run
		#structure
=begin
		NET_API_STATUS NetServerEnum(
		  __in_opt     LPCWSTR servername,
		  __in         DWORD level,
		  __out        LPBYTE *bufptr,
		  __in         DWORD prefmaxlen,
		  __out        LPDWORD entriesread,
		  __out        LPDWORD totalentries,
		  __in         DWORD servertype,
		  __in_opt     LPCWSTR domain,
		  __inout_opt  LPDWORD resume_handle
		);
=end

		client.railgun.add_function('netapi32', 'NetServerEnum', 'DWORD',[
		['PWCHAR','servername','in'],
		['DWORD','level','in'],
		['PDWORD','bufptr','out'],
		['DWORD','prefmaxlen','in'],
		['PDWORD','entriesread','out'],
		['PDWORD','totalentries','out'],
		['DWORD','servertype','in'],
		['PWCHAR','domain','in'],
		['PDWORD','resume_handle','inout']
		])

		domain_enum = 2147483648 # SV_TYPE_DOMAIN_ENUM =  hex 80000000
		buffersize = 500
		result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domain_enum,nil,nil)
		print_status("Finding the right buffersize...")
		while result['return'] == 234
			print_status("Tested #{buffersize}, got #{result['entriesread']} of #{result['totalentries']}")
			buffersize = buffersize + 500
			result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domain_enum,nil,nil)
		end

		count = result['totalentries']
		print_status("#{count} domain(s) found.")
		startmem = result['bufptr']

		base = 0
		domains = []
		mem = client.railgun.memread(startmem, 8*count)
		count.times{|i|
				x = {}
				x[:platform] = mem[(base + 0),4].unpack("V*")[0]
				nameptr = mem[(base + 4),4].unpack("V*")[0]
				x[:domain] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join
				domains << x
				base = base + 8
			}

		domaincontrollers = 24  # 10 + 8 (SV_TYPE_DOMAIN_BAKCTRL || SV_TYPE_DOMAIN_CTRL) 

		domains.each do |x|
			print_status("Enumerating DCs for #{x[:domain]}")
			result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domaincontrollers,x[:domain],nil)
			while result['return'] == 234
				buffersize = buffersize + 500
				result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domaincontrollers,x[:domain],nil)
			end
			if result['totalentries'] == 0
				print_error("No Domain Controllers found...")
				next
			end

			count = result['totalentries']
			startmem = result['bufptr']

			base = 0
			x[:dc] = []
			mem = client.railgun.memread(startmem, 8*count)
			count.times{|i|
				t = {}
				t[:platform] = mem[(base + 0),4].unpack("V*")[0]
				nameptr = mem[(base + 4),4].unpack("V*")[0]
				t[:dc_hostname] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join
				x[:dc] << t
				base = base + 8
				print_status(t[:dc_hostname])
			}
		end
	end
end

