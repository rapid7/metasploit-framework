
module Msf
class Post

module File

	#
	# Check for a file on the remote system
	#
	def file_exist?(file)
		if session.type == "meterpreter"
			stat = session.fs.file.stat(file) rescue nil
			return false unless stat
			return stat.file?
		else
			if session.platform =~ /win/
				# XXX
			else
				f = session.shell_command_token("test -f '#{file}' && echo true")
				return false if f.nil? or f.empty?
				return false unless f =~ /true/
				return true
			end
		end
	end

	#
	# Remove a remote file
	#
	def file_rm(file)
		if session.type == "meterpreter"
			session.fs.file.rm(file)
		else
			if session.platform =~ /win/
				session.shell_command_token("del \"#{file}\"")
			else
				session.shell_command_token("rm -f '#{file}'")
			end
		end
	end

	#
	# Writes a given string to a file specified
	#
	def file_local_write(file2wrt, data2wrt)
		if not ::File.exists?(file2wrt)
			::FileUtils.touch(file2wrt)
		end

		output = ::File.open(file2wrt, "a")
		data2wrt.each_line do |d|
			output.puts(d)
		end
		output.close
	end

	#
	# Returns a MD5 checksum of a given local file
	#
	def file_local_digestmd5(file2md5)
		if not ::File.exists?(file2md5)
			raise "File #{file2md5} does not exists!"
		else
			require 'digest/md5'
			chksum = nil
			chksum = Digest::MD5.hexdigest(::File.open(file2md5, "rb") { |f| f.read})
			return chksum
		end
	end

	#
	# Returns a MD5 checksum of a given remote file
	#

	def file_remote_digestmd5(file2md5)
		data = read_file(file2md5)
		chksum = nil
		if data
			chksum = Digest::MD5.hexdigest(data)
		end
		return chksum
	end

	#
	# Returns a SHA1 checksum of a given local file
	#
	def file_local_digestsha1(file2sha1)
		if not ::File.exists?(file2sha1)
			raise "File #{file2sha1} does not exists!"
		else
			require 'digest/sha1'
			chksum = nil
			chksum = Digest::SHA1.hexdigest(::File.open(file2sha1, "rb") { |f| f.read})
			return chksum
		end
	end

	#
	# Returns a SHA1 checksum of a given remote file
	#
	def file_remote_digestsha1(file2sha1)
		data = read_file(file2sha1)
		chksum = nil
		if data
			chksum = Digest::SHA1.hexdigest(data)
		end
		return chksum
	end

	#
	# Returns a SHA256 checksum of a given local file
	#
	def file_local_digestsha2(file2sha2)
		if not ::File.exists?(file2sha2)
			raise "File #{file2sha2} does not exists!"
		else
			require 'digest/sha2'
			chksum = nil
			chksum = Digest::SHA256.hexdigest(::File.open(file2sha2, "rb") { |f| f.read})
			return chksum
		end
	end

	#
	# Returns a SHA2 checksum of a given remote file
	#
	def file_remote_digestsha2(file2sha2)
		data = read_file(file2sha2)
		chksum = nil
		if data
			chksum = Digest::SHA256.hexdigest(data)
		end
		return chksum
	end

	#
	# Platform-agnostic file read.  Returns contents of remote file +file_name+
	# as a String.
	#
	def read_file(file_name)
		data = nil
		if session.type == "meterpreter"
			data = _read_file_meterpreter(file_name)
		elsif session.type == "shell"
			if session.platform =~ /win/
				data = session.shell_command_token("type \"#{file_name}\"")
			else
				data = session.shell_command_token("cat \'#{file_name}\'")
			end

		end
		data
	end

	#
	# Platform-agnostic file write. Writes given object content to a remote file.
	# Returns Boolean true if successful
	#
	# NOTE: *This is not binary-safe on Windows shell sessions!*
	#
	def write_file(file_name, data)
		if session.type == "meterpreter"
			fd = session.fs.file.new(file_name, "wb")
			fd.write(data)
			fd.close
		elsif session.respond_to? :shell_command_token
			if session.platform =~ /win/
				session.shell_command_token("echo #{data} > \"#{file_name}\"")
			else
				_write_file_unix_shell(file_name, data)
			end

		end
		return true
	end

	#
	# Platform-agnostic file append. Appends given object content to a remote file.
	# Returns Boolean true if successful
	#
	# NOTE: *This is not binary-safe on Windows shell sessions!*
	#
	def append_file(file_name, data)
		if session.type == "meterpreter"
			fd = session.fs.file.new(file_name, "ab")
			fd.write(data)
			fd.close
		elsif session.respond_to? :shell_command_token
			if session.platform =~ /win/
				session.shell_command_token("<nul set /p=\"#{data}\" >> \"#{file_name}\"")
			else
				_write_file_unix_shell(file_name, data, true)
			end
		end
		return true
	end

  #
  # Returns a hash containing the output of "stat" on a remote file
  #
  def stat_file(file_name)
    data = []
    stat = {}

    if session.type == "meterpreter"
      raise "I think you can do this with session.fs.file.stat"
    elsif session.respond_to? :shell_command_token
      print_debug("platform is #{session.platform}")
    case session.platform
      when /windows/
        raise "Windows platform not supported"
      when /linux/
        #  make stat output *almost* like OSX - some of these are just guessed or padded
        stat_cmd = "/usr/bin/stat -c \"%d %i %A %h %U %G %s %t %X %X %Y %Z %b %d %D %n\""
      when /osx/
        # OSX stat gives us less options so we make Linux like this
        stat_cmd = "/usr/bin/stat -t %s"
      end
    end

    data = session.shell_command_token("#{stat_cmd} \'#{file_name}\'").split
    stat = { 'file_name' => data[15],
      'user' => data[4],
      'group' => data[5],
      'inode' => data[1],
      'a_time' => data[9],
      'm_time' => data[10],
      'c_time' => data[11]
    }
    stat 
  end



protected
	#
	# Meterpreter-specific file read.  Returns contents of remote file
	# +file_name+ as a String or nil if there was an error
	#
	# You should never call this method directly.  Instead, call #read_file
	# which will call this if it is appropriate for the given session.
	#
	def _read_file_meterpreter(file_name)
		begin
			fd = session.fs.file.new(file_name, "rb")
		rescue ::Rex::Post::Meterpreter::RequestError => e
			print_error("Failed to open file: #{file_name}")
			return nil
		end

		data = ''
		begin
			until fd.eof?
				data << fd.read
			end
		ensure
			fd.close
		end
		data
	end

	#
	# Write +data+ to the remote file +file_name+.
	#
	# Truncates if +append+ is false, appends otherwise.
	#
	# You should never call this method directly.  Instead, call #write_file or
	# #append_file which will call this if it is appropriate for the given
	# session.
	#
	def _write_file_unix_shell(file_name, data, append=false)
		redirect = (append ? ">>" : ">")

		# Short-circuit an empty string. The : builtin is part of posix
		# standard and should theoretically exist everywhere.
		if data.length == 0
			session.shell_command_token(": #{redirect} #{file_name}")
			return
		end

		d = data.dup
		d.force_encoding("binary") if d.respond_to? :force_encoding

		chunks = []
		command = nil

		line_max = _unix_max_line_length
		# Leave plenty of room for the filename we're writing to and the
		# command to echo it out
		line_max -= file_name.length - 64

		# Default to simple echo. If the data is binary, though, we have to do
		# something fancy
		if d =~ /[^[:print:]]/
			# Ordered by descending likeliness to work
			[
				%q^perl -e 'print("\x41")'^,
				# POSIX awk doesn't have \xNN escapes, use gawk to ensure we're
				# getting the GNU version.
				%q^gawk 'BEGIN {ORS = ""; print "\x41"}' </dev/null^,
				# bash and zsh's echo builtins are apparently the only ones
				# that support both -e and -n as we need them.  Most others
				# treat all options as just more arguments to print. In
				# particular, the standalone /bin/echo or /usr/bin/echo appear
				# never to have -e so don't bother trying them.
				%q^echo -ne '\x41'^,
				# printf seems to have different behavior on bash vs sh vs
				# other shells, try a full path (and hope it's the actual path)
				%q^/usr/bin/printf '\x41'^,
				%q^printf '\x41'^,
			].each { |c|
				a = session.shell_command_token("#{c}")
				if "A" == a
					command = c
					break
				#else
				#	p a
				end
			}

			if command.nil?
				raise RuntimeError, "Can't find command on the victim for writing binary data", caller
			end

			# each byte will balloon up to 4 when we hex encode
			max = line_max/4
			i = 0
			while (i < d.length)
				chunks << Rex::Text.to_hex(d.slice(i...(i+max)))
				i += max
			end
		else
			i = 0
			while (i < d.length)
				chunk = d.slice(i...(i+line_max))
				# POSIX standard says single quotes cannot appear inside single
				# quotes and can't be escaped. Replace them with an equivalent.
				# (Close single quotes, open double quotes containing a single
				# quote, re-open single qutoes)
				chunk.gsub!("'", %q|'"'"'|)
				chunks << chunk
				i += line_max
			end
			command = "echo -n '\\x41'"
		end
		vprint_status("Writing #{d.length} bytes in #{chunks.length} chunks, using #{command.split(" ",2).first}")

		# The first command needs to use the provided redirection for either
		# appending or truncating.
		cmd = command.sub("\\x41", chunks.shift)
		session.shell_command_token("#{cmd} #{redirect} '#{file_name}'")

		# After creating/truncating or appending with the first command, we
		# need to append from here on out.
		chunks.each { |chunk|
			cmd = command.sub("\\x41", chunk)

			session.shell_command_token("#{cmd} >> '#{file_name}'")
		}

		true
	end

	def _unix_max_line_length
		# Based on autoconf's arg_max calculator, see
		# http://www.in-ulm.de/~mascheck/various/argmax/autoconf_check.html
		calc_line_max = 'i=0 max= new= str=abcd; \
			while (test "X"`echo "X$str" 2>/dev/null` = "XX$str") >/dev/null 2>&1 && \
					new=`expr "X$str" : ".*" 2>&1` && \
					test "$i" != 17 && \
					max=$new; do \
				i=`expr $i + 1`; str=$str$str;\
			done; echo $max'
		line_max = session.shell_command_token(calc_line_max).to_i
		line_max = (line_max == 0 ? 4096 : line_max)

		line_max
	end
end

end
end
