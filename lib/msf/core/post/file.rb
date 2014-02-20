# -*- coding: binary -*-

module Msf::Post::File

  #
  # Change directory in the remote session to +path+
  #
  def cd(path)
    if session.type == "meterpreter"
      e_path = session.fs.file.expand_path(path) rescue path
      session.fs.dir.chdir(e_path)
    else
      session.shell_command_token("cd '#{path}'")
    end
  end

  #
  # Returns the current working directory in the remote session
  #
  def pwd
    if session.type == "meterpreter"
      return session.fs.dir.getwd
    else
      if session.platform =~ /win/
        # XXX: %CD% only exists on XP and newer, figure something out for NT4
        # and 2k
        return session.shell_command_token("echo %CD%")
      else
        return session.shell_command_token("pwd")
      end
    end
  end

  #
  # See if +path+ exists on the remote system and is a directory
  #
  def directory?(path)
    if session.type == "meterpreter"
      stat = session.fs.file.stat(path) rescue nil
      return false unless stat
      return stat.directory?
    else
      if session.platform =~ /win/
        f = cmd_exec("cmd.exe /C IF exist \"#{path}\\*\" ( echo true )")
      else
        f = session.shell_command_token("test -d '#{path}' && echo true")
      end

      return false if f.nil? or f.empty?
      return false unless f =~ /true/
      return true
    end
  end

  #
  # Expand any environment variables to return the full path specified by +path+.
  #
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
  def file?(path)
    if session.type == "meterpreter"
      stat = session.fs.file.stat(path) rescue nil
      return false unless stat
      return stat.file?
    else
      if session.platform =~ /win/
        f = cmd_exec("cmd.exe /C IF exist \"#{path}\" ( echo true )")
        if f =~ /true/
          f = cmd_exec("cmd.exe /C IF exist \"#{path}\\\\\" ( echo false ) ELSE ( echo true )")
        end
      else
        f = session.shell_command_token("test -f '#{path}' && echo true")
      end

      return false if f.nil? or f.empty?
      return false unless f =~ /true/
      return true
    end
  end

  alias file_exist? file?

  #
  # Check for existence of +path+ on the remote file system
  #
  def exist?(path)
    if session.type == "meterpreter"
      stat = session.fs.file.stat(path) rescue nil
      return !!(stat)
    else
      if session.platform =~ /win/
         f = cmd_exec("cmd.exe /C IF exist \"#{path}\" ( echo true )")
      else
        f = session.shell_command_token("test -e '#{path}' && echo true")
      end

      return false if f.nil? or f.empty?
      return false unless f =~ /true/
      return true
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
  # Writes a given string to a given local file
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
  # Read a local file +local+ and write it as +remote+ on the remote file
  # system
  #
  def upload_file(remote, local)
    write_file(remote, ::File.read(local))
  end

  #
  # Delete remote files
  #
  def rm_f(*remote_files)
    remote_files.each do |remote|
      if session.type == "meterpreter"
        session.fs.file.delete(remote)
      else
        if session.platform =~ /win/
          cmd_exec("del /q /f #{remote}")
        else
          cmd_exec("rm -f #{remote}")
        end
      end
    end
  end

  #
  # Rename a remote file.
  #
  def rename_file(old_file, new_file)
    if session.respond_to? :commands and session.commands.include?("stdapi_fs_file_move")
      session.fs.file.mv(old_file, new_file)
    else
        if session.platform =~ /win/
          cmd_exec(%Q|move /y "#{old_file}" "#{new_file}"|)
        else
          cmd_exec(%Q|mv -f "#{old_file}" "#{new_file}"|)
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
  def _read_file_meterpreter(file_name)
    begin
      fd = session.fs.file.new(file_name, "rb")
    rescue ::Rex::Post::Meterpreter::RequestError => e
      print_error("Failed to open file: #{file_name}")
      return nil
    end

    data = fd.read
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
      test_str = "\0\xff\xfeABCD\x7f%%\r\n"
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
    session.shell_command_token("#{cmd} #{redirect} '#{file_name}'")

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
