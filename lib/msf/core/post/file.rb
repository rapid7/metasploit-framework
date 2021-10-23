# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/stdapi/command_ids'
require 'rex/post/file_stat'

module Msf::Post::File
  include Msf::Post::Common

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_*
              stdapi_fs_chdir
              stdapi_fs_delete_dir
              stdapi_fs_delete_file
              stdapi_fs_file_expand_path
              stdapi_fs_file_move
              stdapi_fs_getwd
              stdapi_fs_ls
              stdapi_fs_mkdir
              stdapi_fs_stat
            ]
          }
        }
      )
      )
  end

  #
  # Change directory in the remote session to +path+, which may be relative or
  # absolute.
  #
  # @return [void]
  def cd(path)
    e_path = begin
      expand_path(path)
    rescue StandardError
      path
    end
    if session.type == 'meterpreter'
      session.fs.dir.chdir(e_path)
    elsif session.type == 'powershell'
      cmd_exec("Set-Location -Path \"#{e_path}\"")
    else
      session.shell_command_token("cd \"#{e_path}\"")
    end
    nil
  end

  #
  # Returns the current working directory in the remote session
  #
  # @note This may be inaccurate on shell sessions running on Windows before
  #   XP/2k3
  #
  # @return [String]
  def pwd
    if session.type == 'meterpreter'
      return session.fs.dir.getwd
    elsif session.type == 'powershell'
      return cmd_exec('(Get-Location).Path').strip
    elsif session.platform == 'windows'
      return session.shell_command_token('echo %CD%').to_s.strip
    # XXX: %CD% only exists on XP and newer, figure something out for NT4
    # and 2k
    elsif command_exists?('pwd')
      return session.shell_command_token('pwd').to_s.strip
    else
      # Result on systems without pwd command
      return session.shell_command_token('echo $PWD').to_s.strip
    end
  end

  # Returns a list of the contents of the specified directory
  # @param directory [String] the directory to list
  # @return [Array] the contents of the directory
  def dir(directory)
    if session.type == 'meterpreter'
      return session.fs.dir.entries(directory)
    end

    if session.type == 'powershell'
      dir = session.shell_command_token("Get-ChildItem -f \"#{directory}\" | Format-Table Name").split(/[\r\n]+/)
      dir.slice!(0..2) if dir.length > 2
      return dir
    end

    if session.platform == 'windows'
      return session.shell_command_token("dir /b \"#{directory}\"")&.split(/[\r\n]+/)
    end

    if command_exists?('ls')
      return session.shell_command_token("ls #{directory}").split(/[\r\n]+/)
    end

    # Result on systems without ls command
    if directory[-1] != '/'
      directory += '/'
    end
    result = []
    data = session.shell_command_token("for fn in #{directory}*; do echo $fn; done")
    parts = data.split("\n")
    parts.each do |line|
      line = line.split('/')[-1]
      result.insert(-1, line)
    end

    result
  end

  alias ls dir

  # create and mark directory for cleanup
  def mkdir(path)
    result = nil
    vprint_status("Creating directory #{path}")
    if session.type == 'meterpreter'
      # behave like mkdir -p and don't throw an error if the directory exists
      result = session.fs.dir.mkdir(path) unless directory?(path)
    elsif session.type == 'powershell'
      result = cmd_exec("New-Item \"#{path}\" -itemtype directory")
    elsif session.platform == 'windows'
      result = cmd_exec("mkdir \"#{path}\"")
    else
      result = cmd_exec("mkdir -p '#{path}'")
    end
    vprint_status("#{path} created")
    register_dir_for_cleanup(path)
    result
  end

  #
  # See if +path+ exists on the remote system and is a directory
  #
  # @param path [String] Remote filename to check
  def directory?(path)
    if session.type == 'meterpreter'
      stat = begin
        session.fs.file.stat(path)
      rescue StandardError
        nil
      end
      return false unless stat

      return stat.directory?
    elsif session.type == 'powershell'
      return cmd_exec("Test-Path -Path \"#{path}\" -PathType Container").include?('True')
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
    if session.type == 'meterpreter'
      return session.fs.file.expand_path(path)
    elsif session.type == 'powershell'
      return cmd_exec("[Environment]::ExpandEnvironmentVariables(\"#{path}\")")
    else
      return cmd_exec("echo #{path}")
    end
  end

  #
  # See if +path+ exists on the remote system and is a regular file
  #
  # @param path [String] Remote filename to check
  def file?(path)
    return false if path.nil?

    if session.type == 'meterpreter'
      stat = begin
        session.fs.file.stat(path)
      rescue StandardError
        nil
      end
      return false unless stat

      return stat.file?
    elsif session.type == 'powershell'
      return cmd_exec("[System.IO.File]::Exists( \"#{path}\")")&.include?('True')
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
    stat = stat(path)
    stat.setuid?
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
    verification_token = Rex::Text.rand_text_alpha_upper(8)
    if session.type == 'powershell' && file?(path)
      return cmd_exec("$a=[System.IO.File]::OpenWrite('#{path}');if($?){echo #{verification_token}};$a.Close()").include?(verification_token)
    end
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
    verification_token = Rex::Text.rand_text_alpha(8)
    return false unless exists?(path)

    if session.type == 'powershell'
      if directory?(path)
        return cmd_exec("[System.IO.Directory]::GetFiles('#{path}'); if($?) {echo #{verification_token}}").include?(verification_token)
      else
        return cmd_exec("[System.IO.File]::OpenRead(\"#{path}\");if($?){echo\
          #{verification_token}}").include?(verification_token)
      end
    end

    raise "`readable?' method does not support Windows systems" if session.platform == 'windows'

    cmd_exec("test -r '#{path}' && echo #{verification_token}").to_s.include?(verification_token)
  end

  #
  # Check for existence of +path+ on the remote file system
  #
  # @param path [String] Remote filename to check
  def exist?(path)
    if session.type == 'meterpreter'
      stat = begin
        session.fs.file.stat(path)
      rescue StandardError
        nil
      end
      return !!stat
    elsif session.type == 'powershell'
      return cmd_exec("[System.IO.File]::Exists( \"#{path}\")")&.include?('True')
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

  alias exists? exist?

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
    fname = Rex::FileUtils.clean_path(local_file_name)
    unless ::File.exist?(fname)
      ::FileUtils.touch(fname)
    end
    output = ::File.open(fname, 'a')
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

    return unless %w[shell powershell].include?(session.type)

    if session.type == 'powershell'
      return _read_file_powershell(file_name)
    end

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
  # @param file_name [String] Remote file name to write
  # @param data [String] Contents to put in the file
  # @return [void]
  def write_file(file_name, data)
    if session.type == 'meterpreter'
      fd = session.fs.file.new(file_name, 'wb')
      fd.write(data)
      fd.close
    elsif session.type == 'powershell'
      _write_file_powershell(file_name, data)
    elsif session.respond_to? :shell_command_token
      if session.platform == 'windows'
        if _can_echo?(data)
          return _win_ansi_write_file(file_name, data)
        else
          return _win_bin_write_file(file_name, data)
        end
      else
        return _write_file_unix_shell(file_name, data)
      end
    end
  end

  #
  # Platform-agnostic file append. Appends given object content to a remote file.
  #
  # @param file_name [String] Remote file name to write
  # @param data [String] Contents to put in the file
  # @return bool
  def append_file(file_name, data)
    if session.type == 'meterpreter'
      fd = session.fs.file.new(file_name, 'ab')
      fd.write(data)
      fd.close
    elsif session.type == 'powershell'
      _append_file_powershell(file_name, data)
    elsif session.respond_to? :shell_command_token
      if session.platform == 'windows'
        if _can_echo?(data)
          return _win_ansi_append_file(file_name, data)
        else
          return _win_bin_append_file(file_name, data)
        end
      else
        return _write_file_unix_shell(file_name, data)
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
  def chmod(path, mode = 0o700)
    if session.platform == 'windows'
      raise "`chmod' method does not support Windows systems"
    end

    if session.type == 'meterpreter' && session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_FS_CHMOD)
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
    file_path = ::File.join(::Msf::Config.data_directory, 'exploits', data_directory, file)
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
      if session.type == 'meterpreter'
        session.fs.file.delete(remote) if file?(remote)
      elsif session.type == 'powershell'
        cmd_exec("[System.IO.File]::Delete(\"#{remote}\")") if file?(remote)
      elsif session.platform == 'windows'
        cmd_exec("del /q /f \"#{remote}\"")
      else
        cmd_exec("rm -f \"#{remote}\"")
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
      if session.type == 'meterpreter'
        session.fs.dir.rmdir(remote) if exist?(remote)
      elsif session.type == 'powershell'
        cmd_exec("Remove-Item -Path \"#{remote}\" -Force -Recurse")
      elsif session.platform == 'windows'
        cmd_exec("rd /s /q \"#{remote}\"")
      else
        cmd_exec("rm -rf \"#{remote}\"")
      end
    end
  end
  alias file_rm rm_f
  alias dir_rm rm_rf

  #
  # Renames a remote file. If the new file path is a directory, the file will be
  # moved into that directory with the same name.
  #
  # @param old_file [String] Remote file name to move
  # @param new_file [String] The new name for the remote file
  # @return [Boolean] Return true on success and false on failure
  def rename_file(old_file, new_file)
    verification_token = Rex::Text.rand_text_alphanumeric(8)
    if session.type == 'meterpreter'
      begin
        new_file = new_file + session.fs.file.separator + session.fs.file.basename(old_file) if directory?(new_file)
        return (session.fs.file.mv(old_file, new_file).result == 0)
      rescue Rex::Post::Meterpreter::RequestError => e
        return false
      end
    elsif session.type == 'powershell'
      cmd_exec("Move-Item \"#{old_file}\" \"#{new_file}\" -Force; if($?){echo #{verification_token}}").include?(verification_token)
    elsif session.platform == 'windows'
      return false unless file?(old_file) # adding this because when the old_file is not present it hangs for a while, should be removed after this issue is fixed.

      cmd_exec(%(move #{directory?(new_file) ? '' : '/y'} "#{old_file}" "#{new_file}" & if not errorlevel 1 echo #{verification_token})).include?(verification_token)
    else
      cmd_exec(%(mv #{directory?(new_file) ? '' : '-f'} "#{old_file}" "#{new_file}" && echo #{verification_token})).include?(verification_token)
    end
  end
  alias move_file rename_file
  alias mv_file rename_file

  #
  #
  # Copy a remote file.
  #
  # @param src_file [String] Remote source file name to copy
  # @param dst_file [String] The name for the remote destination file
  # @return [Boolean] Return true on success and false on failure
  def copy_file(src_file, dst_file)
    return false if directory?(dst_file) || directory?(src_file)

    verification_token = Rex::Text.rand_text_alpha_upper(8)
    if session.type == 'meterpreter'
      begin
        return (session.fs.file.cp(src_file, dst_file).result == 0)
      rescue Rex::Post::Meterpreter::RequestError => e # when the source file is not present meterpreter will raise an error
        return false
      end
    elsif session.type == 'powershell'
      cmd_exec("Copy-Item \"#{src_file}\" -Destination \"#{dst_file}\"; if($?){echo #{verification_token}}").include?(verification_token)
    elsif session.platform == 'windows'
      cmd_exec(%(copy /y "#{src_file}" "#{dst_file}" & if not errorlevel 1 echo #{verification_token})).include?(verification_token)
    else
      cmd_exec(%(cp -f "#{src_file}" "#{dst_file}" && echo #{verification_token})).include?(verification_token)
    end
  end
  alias cp_file copy_file

  protected

  def _append_file_powershell(file_name, data)
    _write_file_powershell(file_name, data, true)
  end

  def _write_file_powershell(file_name, data, append = false)
    offset = 0
    chunk_size = 16256
    loop do
      _write_file_powershell_fragment(file_name, data, offset, chunk_size, append)
      offset += chunk_size + 1
      break if offset >= data.length
    end
  end

  def _write_file_powershell_fragment(file_name, data, offset, chunk_size, append = false)
    chunk = data[offset..offset + chunk_size]
    length = chunk.length
    compressed_chunk = Rex::Text.gzip(chunk)
    encoded_chunk = Base64.strict_encode64(compressed_chunk)
    if offset > 0 || append
      file_mode = 'Append'
    else
      file_mode = 'Create'
    end
    pwsh_code = %($encoded=\"#{encoded_chunk}\";
    $mstream = [System.IO.MemoryStream]::new([System.Convert]::FromBase64String($encoded));
    $reader = [System.IO.StreamReader]::new([System.IO.Compression.GZipStream]::new($mstream,[System.IO.Compression.CompressionMode]::Decompress));
    $filename = [System.IO.File]::Open('#{file_name}', [System.IO.FileMode]::#{file_mode})
    $file_bytes=[System.Byte[]]::CreateInstance([System.Byte],#{length});
    $reader.BaseStream.Read($file_bytes,0,$file_bytes.Length);
    $filename.Write($file_bytes, 0, $file_bytes.Length);
    $filename.Close();
    $mstream.Close();
    $reader.Close();)
    cmd_exec(pwsh_code)
  end

  def _read_file_powershell(filename)
    data = ''
    offset = 0
    chunk_size = 65536
    loop do
      chunk = _read_file_powershell_fragment(filename, chunk_size, offset)
      break if chunk.nil?

      data << chunk
      offset += chunk_size
      break if chunk.length < chunk_size
    end
    return data
  end

  def _read_file_powershell_fragment(filename, chunk_size, offset = 0)
    b64_data = cmd_exec("$mstream = [System.IO.MemoryStream]::new();\
      $gzipstream = [System.IO.Compression.GZipStream]::new($mstream, [System.IO.Compression.CompressionMode]::Compress);\
      $get_bytes = [System.IO.File]::ReadAllBytes(\"#{filename}\")[#{offset}..#{offset + chunk_size - 1}];\
      $gzipstream.Write($get_bytes, 0 , $get_bytes.Length);\
      $gzipstream.Close();\
      [Convert]::ToBase64String($mstream.ToArray())")
    return nil if b64_data.empty?

    uncompressed_fragment = Zlib::GzipReader.new(StringIO.new(Base64.decode64(b64_data))).read
    return uncompressed_fragment
  end

  # Checks to see if there are non-ansi or newline characters in a given string
  #
  # @param data [String] String to check for non-ansi or newline chars
  # @return bool
  def _can_echo?(data)
    data.each_char do |char|
      unless char.ascii_only? || char == '\n' || char == '"'
        return false
      end
    end
    return true
  end

  #
  # Meterpreter-specific file read.  Returns contents of remote file
  # +file_name+ as a String or nil if there was an error
  #
  # You should never call this method directly.  Instead, call {#read_file}
  # which will call this if it is appropriate for the given session.
  #
  # @return [String]
  def _read_file_meterpreter(file_name)
    fd = session.fs.file.new(file_name, 'rb')

    data = fd.read
    data << fd.read until fd.eof?

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

  # Windows ANSI file write for shell sessions. Writes given object content to a remote file.
  #
  # NOTE: *This is not binary-safe on Windows shell sessions!*
  #
  # @param file_name [String] Remote file name to write
  # @param data [String] Contents to put in the file
  # @param chunk_size [int] max size for the data chunk to write at a time
  # @return [void]
  def _win_ansi_write_file(file_name, data, chunk_size = 5000)
    start_index = 0
    write_length = [chunk_size, data.length].min
    session.shell_command_token("echo | set /p=\"#{data[0, write_length]}\"> \"#{file_name}\"")
    if data.length > write_length
      # just use append to finish the rest
      _win_ansi_append_file(file_name, data[write_length, data.length], chunk_size)
    end
  end

  # Windows ansi file append for shell sessions. Writes given object content to a remote file.
  #
  # NOTE: *This is not binary-safe on Windows shell sessions!*
  #
  # @param file_name [String] Remote file name to write
  # @param data [String] Contents to put in the file
  # @param chunk_size [int] max size for the data chunk to write at a time
  # @return [void]
  def _win_ansi_append_file(file_name, data, chunk_size = 5000)
    start_index = 0
    write_length = [chunk_size, data.length].min
    while start_index < data.length
      begin
        session.shell_command_token("<nul set /p=\"#{data[start_index, write_length]}\" >> \"#{file_name}\"")
        start_index += write_length
        write_length = [chunk_size, data.length - start_index].min
      rescue ::Exception => e
        print_error("Exception while running #{__method__}: #{e}")
        file_rm(file_name)
      end
    end
  end

  # Windows binary file write for shell sessions. Writes given object content to a remote file.
  #
  # @param file_name [String] Remote file name to write
  # @param data [String] Contents to put in the file
  # @param chunk_size [int] max size for the data chunk to write at a time
  # @return [void]
  def _win_bin_write_file(file_name, data, chunk_size = 5000)
    b64_data = Base64.strict_encode64(data)
    b64_filename = "#{file_name}.b64"
    begin
      _win_ansi_write_file(b64_filename, b64_data, chunk_size)
      cmd_exec("certutil -decode #{b64_filename} #{file_name}")
    rescue ::Exception => e
      print_error("Exception while running #{__method__}: #{e}")
    ensure
      file_rm(b64_filename)
    end
  end

  # Windows binary file append for shell sessions. Appends given object content to a remote file.
  #
  # @param file_name [String] Remote file name to write
  # @param data [String] Contents to put in the file
  # @param chunk_size [int] max size for the data chunk to write at a time
  # @return [void]
  def _win_bin_append_file(file_name, data, chunk_size = 5000)
    b64_data = Base64.strict_encode64(data)
    b64_filename = "#{file_name}.b64"
    tmp_filename = "#{file_name}.tmp"
    begin
      _win_ansi_write_file(b64_filename, b64_data, chunk_size)
      cmd_exec("certutil -decode #{b64_filename} #{tmp_filename}")
      cmd_exec("copy /b #{file_name}+#{tmp_filename} #{file_name}")
    rescue ::Exception => e
      print_error("Exception while running #{__method__}: #{e}")
    ensure
      file_rm(b64_filename)
      file_rm(tmp_filename)
    end
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
  def _write_file_unix_shell(file_name, data, append = false)
    redirect = (append ? '>>' : '>')

    # Short-circuit an empty string. The : builtin is part of posix
    # standard and should theoretically exist everywhere.
    if data.empty?
      session.shell_command_token(": #{redirect} #{file_name}")
      return
    end

    d = data.dup
    d.force_encoding('binary') if d.respond_to? :force_encoding

    chunks = []
    command = nil
    encoding = :hex
    cmd_name = ''

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
      { cmd: %q{/usr/bin/printf 'CONTENTS'}, enc: :octal, name: 'printf' },
      { cmd: %q{printf 'CONTENTS'}, enc: :octal, name: 'printf' },
      # Works on Solaris
      { cmd: %q{/usr/bin/printf %b 'CONTENTS'}, enc: :octal, name: 'printf' },
      { cmd: %q{printf %b 'CONTENTS'}, enc: :octal, name: 'printf' },
      # Perl supports both octal and hex escapes, but octal is usually
      # shorter (e.g. 0 becomes \0 instead of \x00)
      { cmd: %q{perl -e 'print("CONTENTS")'}, enc: :octal, name: 'perl' },
      # POSIX awk doesn't have \xNN escapes, use gawk to ensure we're
      # getting the GNU version.
      { cmd: %q^gawk 'BEGIN {ORS="";print "CONTENTS"}' </dev/null^, enc: :hex, name: 'awk' },
      # xxd's -p flag specifies a postscript-style hexdump of unadorned hex
      # digits, e.g. ABCD would be 41424344
      { cmd: %q{echo 'CONTENTS'|xxd -p -r}, enc: :bare_hex, name: 'xxd' },
      # Use echo as a last resort since it frequently doesn't support -e
      # or -n.  bash and zsh's echo builtins are apparently the only ones
      # that support both.  Most others treat all options as just more
      # arguments to print. In particular, the standalone /bin/echo or
      # /usr/bin/echo appear never to have -e so don't bother trying
      # them.
      { cmd: %q{echo -ne 'CONTENTS'}, enc: :hex },
    ].each do |foo|
      # Some versions of printf mangle %.
      test_str = "\0\xff\xfe#{Rex::Text.rand_text_alpha_upper(4)}\x7f%%\r\n"
      # test_str = "\0\xff\xfe"
      case foo[:enc]
      when :hex
        cmd = foo[:cmd].sub('CONTENTS') { Rex::Text.to_hex(test_str) }
      when :octal
        cmd = foo[:cmd].sub('CONTENTS') { Rex::Text.to_octal(test_str) }
      when :bare_hex
        cmd = foo[:cmd].sub('CONTENTS') { Rex::Text.to_hex(test_str, '') }
      end
      a = session.shell_command_token(cmd.to_s)

      if test_str == a
        command = foo[:cmd]
        encoding = foo[:enc]
        cmd_name = foo[:name]
        break
      else
        vprint_status("#{cmd} Failed: #{a.inspect} != #{test_str.inspect}")
      end
    end

    if command.nil?
      raise RuntimeError, "Can't find command on the victim for writing binary data", caller
    end

    # each byte will balloon up to 4 when we encode
    # (A becomes \x41 or \101)
    max = line_max / 4

    i = 0
    while (i < d.length)
      slice = d.slice(i...(i + max))
      case encoding
      when :hex
        chunks << Rex::Text.to_hex(slice)
      when :octal
        chunks << Rex::Text.to_octal(slice)
      when :bare_hex
        chunks << Rex::Text.to_hex(slice, '')
      end
      i += max
    end

    vprint_status("Writing #{d.length} bytes in #{chunks.length} chunks of #{chunks.first.length} bytes (#{encoding}-encoded), using #{cmd_name}")

    # The first command needs to use the provided redirection for either
    # appending or truncating.
    cmd = command.sub('CONTENTS') { chunks.shift }
    session.shell_command_token("#{cmd} #{redirect} \"#{file_name}\"")

    # After creating/truncating or appending with the first command, we
    # need to append from here on out.
    chunks.each do |chunk|
      vprint_status("Next chunk is #{chunk.length} bytes")
      cmd = command.sub('CONTENTS') { chunk }

      session.shell_command_token("#{cmd} >> '#{file_name}'")
    end

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

  def stat(filename)
    if session.type == 'meterpreter'
      return session.fs.file.stat(filename)
    else
      raise NotImplementedError if session.platform == 'windows'
      raise "`stat' command doesn't exist on target system" unless command_exists?('stat')

      return FileStat.new(filename, session)
    end
  end

  class FileStat < Rex::Post::FileStat

    attr_accessor :stathash

    def initialize(filename, session)
      data = session.shell_command_token("stat --format='%d,%i,%h,%u,%g,%t,%s,%B,%o,%X,%Y,%Z,%f' '#{filename}'").to_s.chomp
      raise 'format argument of stat command not behaving as expected' unless data =~ /(\d+,){12}\w+/

      data = data.split(',')
      @stathash = Hash.new
      @stathash['st_dev'] = data[0].to_i
      @stathash['st_ino'] = data[1].to_i
      @stathash['st_nlink'] = data[2].to_i
      @stathash['st_uid'] = data[3].to_i
      @stathash['st_gid'] = data[4].to_i
      @stathash['st_rdev'] = data[5].to_i
      @stathash['st_size'] = data[6].to_i
      @stathash['st_blksize'] = data[7].to_i
      @stathash['st_blocks'] = data[8].to_i
      @stathash['st_atime'] = data[9].to_i
      @stathash['st_mtime'] = data[10].to_i
      @stathash['st_ctime'] = data[11].to_i
      @stathash['st_mode'] = data[12].to_i(16) # stat command returns hex value of mode"
    end
  end
end
