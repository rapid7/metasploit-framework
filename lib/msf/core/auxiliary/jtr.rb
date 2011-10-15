require 'open3'
require 'rex/proto/ntlm/crypt'

module Msf

###
#
# This module provides methods for working with John the Ripper
#
###
module Auxiliary::JohnTheRipper
	include Msf::Auxiliary::Report

	#
	# Initializes an instance of an auxiliary module that calls out to John the Ripper (jtr)
	#

	def initialize(info = {})
		super

		register_options(
			[
				OptPath.new('JOHN_BASE', [false, 'The directory containing John the Ripper (src, run, doc)']),
				OptPath.new('JOHN_PATH', [false, 'The absolute path to the John the Ripper executable'])
			], Msf::Auxiliary::JohnTheRipper
		)

		@run_path  = nil
		@john_path = ::File.join(Msf::Config.install_root, "data", "john")

		autodetect_platform
	end

	def autodetect_platform
		cpuinfo_base = ::File.join(Msf::Config.install_root, "data", "cpuinfo")

		case ::RUBY_PLATFORM
		when /mingw|cygwin|mswin/
			data = `"#{cpuinfo_base}/cpuinfo.exe"`
			case data
			when /sse2/
				@run_path = "run.win32.sse2/john.exe"
			when /mmx/
				@run_path = "run.win32.mmx/john.exe"
			else
				@run_path = "run.win32.any/john.exe"
			end
		when /x86_64-linux/
			data = `#{cpuinfo_base}/cpuinfo.ia64.bin`
			case data
			when /mmx/
				@run_path = "run.linux.x64.mmx/john"
			else
				@run_path = "run.linux.x86.any/john"
			end
		when /i[\d]86-linux/
			data = `#{cpuinfo_base}/cpuinfo.ia32.bin`
			case data
			when /sse2/
				@run_path = "run.linux.x86.sse2/john"
			when /mmx/
				@run_path = "run.linux.x86.mmx/john"
			else
				@run_path = "run.linux.x86.any/john"
			end
		end
	end

	def john_session_id
		@session_id ||= ::Rex::Text.rand_text_alphanumeric(8)
	end

	def john_cracked_passwords
		ret = {}
		pot = ::File.join( ::File.dirname( john_binary_path ), "john.pot" )
		return ret if not ::File.exist?(pot)
		::File.open(pot, "rb") do |fd|
			fd.each_line do |line|
				hash,clear = line.sub(/\r?\n$/, '').split(",", 2)
				ret[hash] = clear
			end
		end
		ret
	end

	def john_show_passwords(hfile, format=nil)
		res = {:cracked => 0, :uncracked => 0, :users => {} }
		cmd = [ john_binary_path,  "--show", "--conf=" + ::File.join(john_base_path, "confs", "john.conf"), hfile]
		if format
			cmd << "--format=" + format
		end

		if RUBY_VERSION =~ /^1\.8\./
			cmd = cmd.join(" ")
		end

		::IO.popen(cmd, "rb") do |fd|
			fd.each_line do |line|
				if line =~ /(\d+) password hash cracked, (\d+) left/m
					res[:cracked]   = $1.to_i
					res[:uncracked] = $2.to_i
				end

				bits = line.split(':')
				next if not bits[2]
				res[ :users ][ bits[0] ] = bits[1]
			end
		end
		res
	end

	def john_wordlist_path
		::File.join(john_base_path, "wordlists", "password.lst")
	end

	def john_binary_path
		if datastore['JOHN_PATH'] and ::File.file?(datastore['JOHN_PATH'])
			return datastore['JOHN_PATH']
		end
		if not @run_path
			if ::RUBY_PLATFORM =~ /mingw|cygwin|mswin/
				::File.join(john_base_path, "john.exe")
			else
				::File.join(john_base_path, "john")
			end
		else
			::File.join(john_base_path, @run_path)
		end
	end

	def john_base_path
		if datastore['JOHN_BASE'] and ::File.directory?(datastore['JOHN_BASE'])
			return datastore['JOHN_BASE']
		end
		if datastore['JOHN_PATH'] and ::File.file?(datastore['JOHN_PATH'])
			return ::File.dirname( datastore['JOHN_PATH'] )
		end
		@john_path
	end

	def john_expand_word(str)
		res = [str]
		str.split(/\W+/) {|w| res << w }
		res.uniq
	end

	def john_lm_upper_to_ntlm(pwd, hash)
		pwd  = pwd.upcase
		hash = hash.upcase
		Rex::Text.permute_case(pwd).each do |str|
			if hash == Rex::Proto::NTLM::Crypt.ntlm_hash(str).unpack("H*")[0].upcase
				return str
			end
		end
		nil
	end


	def john_crack(hfile, opts={})

		res = {:cracked => 0, :uncracked => 0, :users => {} }

		cmd = [ john_binary_path,  "--session=" + john_session_id]

		if opts[:conf]
			cmd << ( "--conf=" + opts[:conf] )
		else
			cmd << ( "--conf=" + ::File.join(john_base_path, "confs", "john.conf") )
		end

		if opts[:format]
			cmd << ( "--format=" + opts[:format] )
		end

		if opts[:wordlist]
			cmd << ( "--wordlist=" + opts[:wordlist] )
		end

		if opts[:incremental]
			cmd << ( "--incremental=" + opts[:incremental] )
		end

		if opts[:single]
			cmd << ( "--single=" + opts[:single] )
		end

		if opts[:rules]
			cmd << ( "--rules=" + opts[:rules] )
		end

		cmd << hfile

		if RUBY_VERSION =~ /^1\.8\./
			cmd = cmd.join(" ")
		end

		::IO.popen(cmd, "rb") do |fd|
			fd.each_line do |line|
				print_status("Output: #{line.strip}")
			end
		end

		# Clean up temporary files created by --session
		# XXX: Surely there is a better way to control
		#      the location of these.
		::FileUtils.rm_f("#{john_session_id}.log")

		res
	end
end
end

