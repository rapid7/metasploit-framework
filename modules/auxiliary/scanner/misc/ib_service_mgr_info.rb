##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp

	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'		=> 'Borland InterBase Services Manager Information',
			'Description'	=> %q{
				This module retrieves version of the services manager, version
				and implementation of the InterBase server from InterBase
				Services Manager.
			},
			'Author'	=>
				[
					'Ramon de C Valle',
					'Adriano Lima <adriano[at]risesecurity.org>',
				],
			'License'	=> MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(3050)
			],
			self.class
		)

	end

	# Create service parameter block
	def spb_create
		isc_dpb_user_name = 28
		isc_dpb_password = 29

		isc_spb_user_name = isc_dpb_user_name
		isc_spb_password = isc_dpb_password

		isc_spb_current_version = 2
		isc_spb_version = isc_spb_current_version

		user = 'SYSDBA'
		pass = 'masterkey'

		spb = ''

		spb << [isc_spb_version].pack('c')
		spb << [isc_spb_current_version].pack('c')

		spb << [isc_spb_user_name].pack('c')
		spb << [user.length].pack('c')
		spb << user

		spb << [isc_spb_password].pack('c')
		spb << [pass.length].pack('c')
		spb << pass

		spb
	end

	# Create receive buffer
	def recv_spb_create
		# Retrieves the version of the services manager
		isc_info_svc_version = 54

		# Retrieves the version of the InterBase server
		isc_info_svc_server_version = 55

		# Retrieves the implementation of the InterBase server
		isc_info_svc_implementation = 56

		recv_spb = ''

		recv_spb << [isc_info_svc_version].pack('c')
		recv_spb << [isc_info_svc_server_version].pack('c')
		recv_spb << [isc_info_svc_implementation].pack('c')

		recv_spb
	end

	# Calculate buffer padding
	def buf_padding(length = '')
		remainder = length.remainder(4)
		padding = 0

		if remainder > 0
			padding = (4 - remainder)
		end

		padding
	end

	def run_host(ip)

		#
		# Using the InterBase Services Manager
		# http://dn.codegear.com/article/27002
		#

		begin

			print_status("Trying #{ip}")

			connect

			# isc_service_attach

			# Service name
			svc_name = 'service_mgr'

			# Service attach
			op_service_attach = 82

			buf = ''

			# Operation/packet type
			buf << [op_service_attach].pack('N')

			# Id
			buf << [0].pack('N')

			# Length
			buf << [svc_name.length].pack('N')

			# Service name
			buf << svc_name

			# Padding
			buf << "\x00" * buf_padding(svc_name.length)

			# Create service parameter block
			spb = spb_create

			# Service parameter block length
			buf << [spb.length].pack('N')

			# Service parameter block
			buf << spb

			# Padding
			buf << "\x00" * buf_padding(spb.length)

			sock.put(buf)

			response = sock.get_once

			# print(Rex::Text.to_hex_dump(response))


			# isc_service_query

			# Response buffer length
			response_buffer_length = 64

			# Service info
			op_service_info = 84

			buf = ''

			# Operation/packet type
			buf << [op_service_info].pack('N')

			# Id
			buf << [0].pack('N')

			# ?
			buf << [0].pack('N')

			# ?
			buf << [0].pack('N')

			# Create receive buffer
			recv_spb = recv_spb_create

			# Receive buffer length
			buf << [recv_spb.length].pack('N')

			# Receive buffer
			buf << recv_spb

			# Padding
			buf << "\x00" * buf_padding(recv_spb.length)

			# Response buffer length
			buf << [response_buffer_length].pack('N')

			sock.put(buf)

			response = sock.get_once

			res = response.unpack('x28Z*Z*')

			info_svc_server_version = res[0].chop.chop
			info_svc_implementation = res[1].chop

			print("IP Address: #{ip}\n")
			# print("Version of the services manager: #{info_svc_version}\n")
			print("Version of the InterBase server: #{info_svc_server_version}\n")
			print("Implementation of the InterBase server: #{info_svc_implementation}\n\n")

			# print(Rex::Text.to_hex_dump(response))

			#Add Report
			report_note(
				:host	=> ip,
				:sname	=> 'ib',
				:proto	=> 'tcp',
				:port	=> rport,
				:type	=> 'Version of the InterBase server',
				:data	=> "Version of the InterBase server: #{info_svc_server_version}"
			)

			#Add Report
			report_note(
				:host	=> ip,
				:sname	=> 'ib',
				:proto	=> 'tcp',
				:port	=> rport,
				:type	=> 'Implementation of the InterBase server',
				:data	=> "Implementation of the InterBase server: #{info_svc_implementation}"
			)

		rescue ::Rex::ConnectionError
		rescue ::Errno::EPIPE

		end

	end

end
