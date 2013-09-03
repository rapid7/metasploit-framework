##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::SMB::Authenticated
	include Msf::Exploit::Remote::DCERPC

	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'SMB Domain User Enumeration',
			'Version'     => '$Revision $',
			'Description' => 'Determine what domain users are logged into a remote system via a DCERPC to NetWkstaUserEnum.',
			'Author'      => 'natron',
			'References'  =>
				[
					[ 'URL', 'http://msdn.microsoft.com/en-us/library/aa370669%28VS.85%29.aspx' ]
				],
			'License'     => MSF_LICENSE
		)

		deregister_options('RPORT', 'RHOST')

	end

	def parse_value(resp, idx)
		#val_length  = resp[idx,4].unpack("V")[0]
		idx += 4
		#val_offset = resp[idx,4].unpack("V")[0]
		idx += 4
		val_actual = resp[idx,4].unpack("V")[0]
		idx += 4
		value	= resp[idx,val_actual*2]
		#print_debug "resp[0x#{idx.to_s(16)},#{val_actual*2}] : " + value
		idx += val_actual * 2

		idx += val_actual % 2 * 2 # alignment

		return value,idx
	end

	def parse_NetWkstaEnumUsersInfo(resp)
		accounts = [ Hash.new() ]

		#print_debug resp[0,20].unpack("H*")
		idx = 20
		count = resp[idx,4].unpack("V")[0] # wkssvc_NetWkstaEnumUsersInfo -> Info -> PtrCt0 -> User() -> Ptr -> Max Count
		idx += 4
		#print_debug "Max Count  : " + count.to_s

		1.upto(count) do
			# wkssvc_NetWkstaEnumUsersInfo -> Info -> PtrCt0 -> User() -> Ptr -> Ref ID
			# print_debug "Ref ID#{account.to_s}: " + resp[idx,4].unpack("H*").to_s
			idx += 4 # ref id name
			idx += 4 # ref id logon domain
			idx += 4 # ref id other domains
			idx += 4 # ref id logon server
		end

		1.upto(count) do
			# wkssvc_NetWkstaEnumUsersInfo -> Info -> PtrCt0 -> User() -> Ptr -> ID1 max count

			account_name,idx	= parse_value(resp, idx)
			logon_domain,idx	= parse_value(resp, idx)
			other_domains,idx	= parse_value(resp, idx)
			logon_server,idx	= parse_value(resp, idx)

			accounts << {
				:account_name => account_name,
				:logon_domain => logon_domain,
				:other_domains => other_domains,
				:logon_server => logon_server
			}
		end

		accounts
	end

	def run_host(ip)

		[[139, false], [445, true]].each do |info|

		datastore['RPORT'] = info[0]
		datastore['SMBDirect'] = info[1]

		begin
			connect()
			smb_login()

			uuid = [ '6bffd098-a112-3610-9833-46c3f87e345a', '1.0' ]

			handle = dcerpc_handle(
				uuid[0], uuid[1], 'ncacn_np', ["\\wkssvc"]
			)
			begin
				dcerpc_bind(handle)
				stub =
					NDR.uwstring("\\\\" + ip) +	# Server Name
					NDR.long(1) +						# Level
					NDR.long(1) +						# Ctr
					NDR.long(rand(0xffffffff)) +	# ref id
					NDR.long(0) +						# entries read
					NDR.long(0) +						# null ptr to user0

					NDR.long(0xffffffff) +			# Prefmaxlen
					NDR.long(rand(0xffffffff)) +	# ref id
					NDR.long(0)							# null ptr to resume handle

				dcerpc.call(2,stub)

				resp = dcerpc.last_response ? dcerpc.last_response.stub_data : nil

				accounts = parse_NetWkstaEnumUsersInfo(resp)
				accounts.shift

				if datastore['VERBOSE']
					accounts.each do |x|
						print_status ip + " : " + x[:logon_domain] + "\\" + x[:account_name] +
							"\t(logon_server: #{x[:logon_server]}, other_domains: #{x[:other_domains]})"
					end
				else
					print_status "#{ip} : #{accounts.collect{|x| x[:logon_domain] + "\\" + x[:account_name]}.join(", ")}"
				end

			rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
				print_line("UUID #{uuid[0]} #{uuid[1]} ERROR 0x%.8x" % e.error_code)
				#puts e
				#return
			rescue ::Exception => e
				print_line("UUID #{uuid[0]} #{uuid[1]} ERROR #{$!}")
				#puts e
				#return
			end

			disconnect()
			return
		rescue ::Exception
			print_line($!.to_s)
		end
	end
end

end
