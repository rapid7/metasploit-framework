# -*- coding: binary -*-

module Msf::Post::File

  #
  # Change directory in the remote session to +path+, which may be relative or
  # absolute.
  #
  # @return [void]
  def cd(path)
    e_path = expand_path(path) rescue path
    if session.type == "meterpreter"
      session.fs.dir.chdir(e_path)
    else
      session.shell_command_token("cd \"#{e_path}\"")
    end
  end

  #
  # Returns the current working directory in the remote session
  #
  # @note This may be inaccurate on shell sessions running on Windows before
  #   XP/2k3
  #
  # @return [String]
  def pwd
    if session.type == "meterpreter"
      return session.fs.dir.getwd
    else
      if session.platform == 'windows'
        # XXX: %CD% only exists on XP and newer, figure something out for NT4
        # and 2k
        return session.shell_command_token("echo %CD%")
      else
        if command_exists?("pwd")
          return session.shell_command_token("pwd").to_s.strip
        else
          # Result on systems without pwd command
          return session.shell_command_token("echo $PWD").to_s.strip
        end
      end
    end
  end

  # Returns a list of the contents of the specified directory
  # @param directory [String] the directory to list
  # @return [Array] the contents of the directory
  def dir(directory)
    if session.type == 'meterpreter'
      return session.fs.dir.entries(directory)
    end

    if session.platform == 'windows'
      return session.shell_command_token("dir #{directory}").split(/[\r\n]+/)
    end

    if command_exists?('ls')
      return session.shell_command_token("ls #{directory}").split(/[\r\n]+/)
    end

    # Result on systems without ls command
    if directory[-1] != '/'
      directory = directory + "/"
    end
    result = []
    data = session.shell_command_token("for fn in #{directory}*; do echo $fn; done")
    parts = data.split("\n")
    parts.each do |line|
      line = line.split("/")[-1]
      result.insert(-1, line)
    end

    result
  end

  alias ls dir

  #
  # See if +path+ exists on the remote system and is a directory
  #
  # @param path [String] Remote filename to check
  def directory?(path)
    if session.type == 'meterpreter'
      stat = session.fs.file.stat(path) rescue nil
      return false unless stat
      return stat.directory?
    else
      if session.platform == 'windows'
        f = cmd_exec("cmd.exe /C IF exist \"#{path}\\*\" ( echo true )")
      else
        f = session.shell_command_token("test -d \"#{path}\" && echo true")
      end
      return false if f.nil? || f.empty?
      return false unless f =~ /true/
      true
    end
  end

  #
  # Expand any environment variables to return the full path specified by +path+.
  #
  # @return [String]
  def expand_path(path)
    if session.type == "meterpreter"
      return session.fs.file.expand_path(path)
    else
      return cmd_exec("echo #{path}")
    end
  end

  #
  # See if +path+ exists on the remote system and is a regular file
  #
  # @param path [String] Remote filename to check
  def file?(path)
    if session.type == 'meterpreter'
      stat = session.fs.file.stat(path) rescue nil
      return false unless stat
      return stat.file?
    else
      if session.platform == 'windows'
        f = cmd_exec("cmd.exe /C IF exist \"#{path}\" ( echo true )")
        if f =~ /true/
          f = cmd_exec("cmd.exe /C IF exist \"#{path}\\\\\" ( echo false ) ELSE ( echo true )")
        end
      else
        f = session.shell_command_token("test -f \"#{path}\" && echo true")
      end
      return false if f.nil? || f.empty?
      return false unless f =~ /true/
      true
    end
  end

  alias file_exist? file?

  #
  # See if +path+ on the remote system is a setuid file
  #
  # @param path [String] Remote filename to check
  def setuid?(path)
    if session.type == 'meterpreter'
      stat = session.fs.file.stat(path) rescue nil
      return false unless stat
      return stat.setuid?
    else
      if session.platform != 'windows'
        f = session.shell_command_token("test -u \"#{path}\" && echo true")
      end
      return false if f.nil? || f.empty?
      return false unless f =~ /true/
      true
    end
  end

  #
  # See if +path+ on the remote system exists and is executable
  #
  # @param path [String] Remote path to check
  #
  # @return [Boolean] true if +path+ exists and is executable
  #
  def executable?(path)
    raise "`executable?' method does not support Windows systems" if session.platform == 'windows'

    cmd_exec("test -x '#{path}' && echo true").to_s.include? 'true'
  end

  #
  # See if +path+ on the remote system exists and is writable
  #
  # @param path [String] Remote path to check
  #
  # @return [Boolean] true if +path+ exists and is writable
  #
  def writable?(path)
    raise "`writable?' method does not support Windows systems" if session.platform == 'windows'

    cmd_exec("test -w '#{path}' && echo true").to_s.include? 'true'
  end

  #
  # See if +path+ on the remote system exists and is immutable
  #
  # @param path [String] Remote path to check
  #
  # @return [Boolean] true if +path+ exists and is immutable
  #
  def immutable?(path)
    raise "`immutable?' method does not support Windows systems" if session.platform == 'windows'

    attributes(path).include?('Immutable')
  end

  #
  # See if +path+ on the remote system exists and is readable
  #
  # @param path [String] Remote path to check
  #
  # @return [Boolean] true if +path+ exists and is readable
  #
  def readable?(path)
    raise "`readable?' method does not support Windows systems" if session.platform == 'windows'

    cmd_exec("test -r '#{path}' && echo true").to_s.include? 'true'
  end

  #
  # Check for existence of +path+ on the remote file system
  #
  # @param path [String] Remote filename to check
  def exist?(path)
    if session.type == 'meterpreter'
      stat = session.fs.file.stat(path) rescue nil
      return !!(stat)
    else
      if session.platform == 'windows'
        f = cmd_exec("cmd.exe /C IF exist \"#{path}\" ( echo true )")
      else
        f = cmd_exec("test -e \"#{path}\" && echo true")
      end
      return false if f.nil? || f.empty?
      return false unless f =~ /true/
      true
    end
  end

  alias :exists? :exist?

  #
  # Retrieve file attributes for +path+ on the remote system
  #
  # @param path [String] Remote filename to check
  def attributes(path)
    raise "`attributes' method does not support Windows systems" if session.platform == 'windows'

    cmd_exec("lsattr -l '#{path}'").to_s.scan(/^#{path}\s+(.+)$/).flatten.first.to_s.split(', ')
  end

  #
  # Writes a given string to a given local file
  #
  # @param local_file_name [String]
  # @param data [String]
  # @return [void]
  def file_local_write(local_file_name, data)
    unless ::File.exist?(local_file_name)
      ::FileUtils.touch(local_file_name)
    end
    output = ::File.open(local_file_name, "a")
    data.each_line do |d|
      output.puts(d)
    end
    output.close
  end

  #
  # Returns a MD5 checksum of a given remote file
  #
  # @note THIS DOWNLOADS THE FILE
  # @param file_name [String] Remote file name
  # @return [String] Hex digest of file contents
  def file_remote_digestmd5(file_name)
    data = read_file(file_name)
    chksum = nil
    if data
      chksum = Digest::MD5.hexdigest(data)
    end
    return chksum
  end

  #
  # Returns a SHA1 checksum of a given remote file
  #
  # @note THIS DOWNLOADS THE FILE
  # @param file_name [String] Remote file name
  # @return [String] Hex digest of file contents
  def file_remote_digestsha1(file_name)
    data = read_file(file_name)
    chksum = nil
    if data
      chksum = Digest::SHA1.hexdigest(data)
    end
    return chksum
  end

  #
  # Returns a SHA2 checksum of a given remote file
  #
  # @note THIS DOWNLOADS THE FILE
  # @param file_name [String] Remote file name
  # @return [String] Hex digest of file contents
  def file_remote_digestsha2(file_name)
    data = read_file(file_name)
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
  # @param file_name [String] Remote file name to read
  # @return [String] Contents of the file
  #
  # @return [Array] of strings(lines)
  #
  def read_file(file_name)
    if session.type == 'meterpreter'
      return _read_file_meterpreter(file_name)
    end

    return nil unless session.type == 'shell'

    if session.platform == 'windows'
      return session.shell_command_token("type \"#{file_name}\"")
    end

    return nil unless readable?(file_name)

    if command_exists?('cat')
      return session.shell_command_token("cat \"#{file_name}\"")
    end

    # Result on systems without cat command
    session.shell_command_token("while read line; do echo $line; done <#{file_name}")
  end

  # Platform-agnostic file write. Writes given object content to a remote file.
  #
  # NOTE: *This is not binary-safe on Windows shell sessions!*
  #
  # @param file_name [String] Remote file name to write
  # @param data [String] Contents to put in the file
  # @return [void]
  def write_file(file_name, data)
    if session.type == "meterpreter"
      fd = session.fs.file.new(file_name, "wb")
      fd.write(data)
      fd.close
    elsif session.respond_to? :shell_command_token
      if session.platform == 'windows'
        session.shell_command_token("echo #{data} > \"#{file_name}\"")
      else
        _write_file_unix_shell(file_name, data)
      end
    end
    true
  end

  #
  # Platform-agnostic file append. Appends given object content to a remote file.
  # Returns Boolean true if successful
  #
  # NOTE: *This is not binary-safe on Windows shell sessions!*
  #
  # @param file_name [String] Remote file name to write
  # @param data [String] Contents to put in the file
  # @return [void]
  def append_file(file_name, data)
    if session.type == "meterpreter"
      fd = session.fs.file.new(file_name, "ab")
      fd.write(data)
      fd.close
    elsif session.respond_to? :shell_command_token
      if session.platform == 'windows'
        session.shell_command_token("<nul set /p=\"#{data}\" >> \"#{file_name}\"")
      else
        _write_file_unix_shell(file_name, data, true)
      end
    end
    true
  end

  #
  # Read a local file +local+ and write it as +remote+ on the remote file
  # system
  #
  # @param remote [String] Destination file name on the remote filesystem
  # @param local [String] Local file whose contents will be uploaded
  # @return (see #write_file)
  def upload_file(remote, local)
    write_file(remote, ::File.read(local))
  end

  #
  # Upload a binary and write it as an executable file +remote+ on the
  # remote filesystem.
  #
  # @param remote [String] Destination file name on the remote filesystem
  # @param data [String] Data to be uploaded
  def upload_and_chmodx(path, data)
    print_status "Writing '#{path}' (#{data.size} bytes) ..."
    write_file path, data
    chmod(path)
  end

  #
  # Sets the permissions on a remote file
  #
  # @param path [String] Path on the remote filesystem
  # @param mode [Fixnum] Mode as an octal number
  def chmod(path, mode = 0700)
    if session.platform == 'windows'
      raise "`chmod' method does not support Windows systems"
    end

    if session.type == 'meterpreter' && session.commands.include?('stdapi_fs_chmod')
      session.fs.file.chmod(path, mode)
    else
      cmd_exec("chmod #{mode.to_s(8)} '#{path}'")
    end
  end

  #
  # Read a local exploit file binary from the data directory
  #
  # @param path [String] Directory in the exploits folder
  # @param path [String] Filename in the data folder
  def exploit_data(data_directory, file)
    file_path = ::File.join(::Msf::Config.data_directory, "exploits", data_directory, file)
    ::File.binread(file_path)
  end

  #
  # Delete remote files
  #
  # @param remote_files [Array<String>] List of remote filenames to
  #   delete
  # @return [void]
  def rm_f(*remote_files)
    remote_files.each do |remote|
      if session.type == "meterpreter"
        session.fs.file.delete(remote) if exist?(remote)
      else
        if session.platform == 'windows'
          cmd_exec("del /q /f \"#{remote}\"")
        else
          cmd_exec("rm -f \"#{remote}\"")
        end
      end
    end
  end

  #
  # Delete remote directories
  #
  # @param remote_dirs [Array<String>] List of remote directories to
  #   delete
  # @return [void]
  def rm_rf(*remote_dirs)
    remote_dirs.each do |remote|
      if session.type == "meterpreter"
        session.fs.dir.rmdir(remote) if exist?(remote)
      else
        if session.platform == 'windows'
          cmd_exec("rd /s /q \"#{remote}\"")
        else
          cmd_exec("rm -rf \"#{remote}\"")
        end
      end
    end
  end
  alias :file_rm :rm_f
  alias :dir_rm :rm_rf

  #
  # Rename a remote file.
  #
  # @param old_file [String] Remote file name to move
  # @param new_file [String] The new name for the remote file
  def rename_file(old_file, new_file)
    if session.type == "meterpreter"
      return (session.fs.file.mv(old_file, new_file).result == 0)
    else
      if session.platform == 'windows'
        cmd_exec(%Q|move /y "#{old_file}" "#{new_file}"|) =~ /moved/
      else
        cmd_exec(%Q|mv -f "#{old_file}" "#{new_file}"|).empty?
      end
    end
  end
  alias :move_file :rename_file
  alias :mv_file :rename_file

protected

  #
  # Meterpreter-specific file read.  Returns contents of remote file
  # +file_name+ as a String or nil if there was an error
  #
  # You should never call this method directly.  Instead, call {#read_file}
  # which will call this if it is appropriate for the given session.
  #
  # @return [String]
  def _read_file_meterpreter(file_name)
    fd = session.fs.file.new(file_name, "rb")

    data = fd.read
    until fd.eof?
      data << fd.read
    end

    data
  rescue EOFError
    # Sometimes fd isn't marked EOF in time?
    ''
  rescue ::Rex::Post::Meterpreter::RequestError => e
    print_error("Failed to open file: #{file_name}: #{e}")
    return nil
  ensure
    fd.close if fd
  end

  #
  # Write +data+ to the remote file +file_name+.
  #
  # Truncates if +append+ is false, appends otherwise.
  #
  # You should never call this method directly.  Instead, call {#write_file}
  # or {#append_file} which will call this if it is appropriate for the given
  # session.
  #
  # @return [void]
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
    encoding = :hex
    cmd_name = ""

    line_max = _unix_max_line_length
    # Leave plenty of room for the filename we're writing to and the
    # command to echo it out
    line_max -= file_name.length
    line_max -= 64

    # Ordered by descending likeliness to work
    [
      # POSIX standard requires %b which expands octal (but not hex)
      # escapes in the argument. However, some versions (notably
      # FreeBSD) truncate input on nulls, so "printf %b '\0\101'"
      # produces a 0-length string. Some also allow octal escapes
      # without a format string, and do not truncate, so start with
      # that and try %b if it doesn't work. The standalone version seems
      # to be more likely to work than the buitin version, so try it
      # first.
      #
      # Both of these work for sure on Linux and FreeBSD
      { :cmd => %q^/usr/bin/printf 'CONTENTS'^ , :enc => :octal, :name => "printf" },
      { :cmd => %q^printf 'CONTENTS'^ , :enc => :octal, :name => "printf" },
      # Works on Solaris
      { :cmd => %q^/usr/bin/printf %b 'CONTENTS'^ , :enc => :octal, :name => "printf" },
      { :cmd => %q^printf %b 'CONTENTS'^ , :enc => :octal, :name => "printf" },
      # Perl supports both octal and hex escapes, but octal is usually
      # shorter (e.g. 0 becomes \0 instead of \x00)
      { :cmd => %q^perl -e 'print("CONTENTS")'^ , :enc => :octal, :name => "perl" },
      # POSIX awk doesn't have \xNN escapes, use gawk to ensure we're
      # getting the GNU version.
      { :cmd => %q^gawk 'BEGIN {ORS="";print "CONTENTS"}' </dev/null^ , :enc => :hex, :name => "awk" },
      # xxd's -p flag specifies a postscript-style hexdump of unadorned hex
      # digits, e.g. ABCD would be 41424344
      { :cmd => %q^echo 'CONTENTS'|xxd -p -r^ , :enc => :bare_hex, :name => "xxd" },
      # Use echo as a last resort since it frequently doesn't support -e
      # or -n.  bash and zsh's echo builtins are apparently the only ones
      # that support both.  Most others treat all options as just more
      # arguments to print. In particular, the standalone /bin/echo or
      # /usr/bin/echo appear never to have -e so don't bother trying
      # them.
      { :cmd => %q^echo -ne 'CONTENTS'^ , :enc => :hex },
    ].each { |foo|
      # Some versions of printf mangle %.
      test_str = "\0\xff\xfe#{Rex::Text.rand_text_alpha_upper(4)}\x7f%%\r\n"
      #test_str = "\0\xff\xfe"
      case foo[:enc]
      when :hex
        cmd = foo[:cmd].sub("CONTENTS"){ Rex::Text.to_hex(test_str) }
      when :octal
        cmd = foo[:cmd].sub("CONTENTS"){ Rex::Text.to_octal(test_str) }
      when :bare_hex
        cmd = foo[:cmd].sub("CONTENTS"){ Rex::Text.to_hex(test_str,'') }
      end
      a = session.shell_command_token("#{cmd}")

      if test_str == a
        command = foo[:cmd]
        encoding = foo[:enc]
        cmd_name = foo[:name]
        break
      else
        vprint_status("#{cmd} Failed: #{a.inspect} != #{test_str.inspect}")
      end
    }

    if command.nil?
      raise RuntimeError, "Can't find command on the victim for writing binary data", caller
    end

    # each byte will balloon up to 4 when we encode
    # (A becomes \x41 or \101)
    max = line_max/4

    i = 0
    while (i < d.length)
      slice = d.slice(i...(i+max))
      case encoding
      when :hex
        chunks << Rex::Text.to_hex(slice)
      when :octal
        chunks << Rex::Text.to_octal(slice)
      when :bare_hex
        chunks << Rex::Text.to_hex(slice,'')
      end
      i += max
    end

    vprint_status("Writing #{d.length} bytes in #{chunks.length} chunks of #{chunks.first.length} bytes (#{encoding}-encoded), using #{cmd_name}")

    # The first command needs to use the provided redirection for either
    # appending or truncating.
    cmd = command.sub("CONTENTS") { chunks.shift }
    session.shell_command_token("#{cmd} #{redirect} \"#{file_name}\"")

    # After creating/truncating or appending with the first command, we
    # need to append from here on out.
    chunks.each { |chunk|
      vprint_status("Next chunk is #{chunk.length} bytes")
      cmd = command.sub("CONTENTS") { chunk }

      session.shell_command_token("#{cmd} >> '#{file_name}'")
    }

    true
  end

  #
  # Calculate the maximum line length for a unix shell.
  #
  # @return [Integer]
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

    # Fall back to a conservative 4k which should work on even the most
    # restrictive of embedded shells.
    line_max = (line_max == 0 ? 4096 : line_max)
    vprint_status("Max line length is #{line_max}")

    line_max
  end
end
