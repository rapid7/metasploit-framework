# -*- coding: binary -*-

require 'rex/post/file'
require 'rex/post/meterpreter/channel'
require 'rex/post/meterpreter/channels/pools/file'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'
require 'rex/post/meterpreter/extensions/stdapi/fs/io'
require 'rex/post/meterpreter/extensions/stdapi/fs/file_stat'
require 'fileutils'
require 'filesize'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Stdapi
          module Fs
            ###
            #
            # This class implements the Rex::Post::File interface and wraps interaction
            # with files on the remote machine.
            #
            ###
            class File < Rex::Post::Meterpreter::Extensions::Stdapi::Fs::IO

              include Rex::Post::File

              MIN_BLOCK_SIZE = 1024
              STEP_SKIPPED_WOULD_OVERWRITE = 'Overwrite'
              STEP_COMPLETED = 'Completed'
              STEP_SKIPPED = 'Skipped'
              STEP_COMPLETED_OVERWRITTEN = 'Overwritten'

              class << self
                attr_accessor :client
              end

              #
              # Return the directory separator, i.e.: "/" on unix, "\\" on windows
              #
              def self.separator
                # The separator won't change, so cache it to prevent sending
                # unnecessary requests.
                return @separator if @separator

                request = Packet.create_request(COMMAND_ID_STDAPI_FS_SEPARATOR)

                # Fall back to the old behavior of always assuming windows.  This
                # allows meterpreter executables built before the addition of this
                # command to continue functioning.
                begin
                  response = client.send_request(request)
                  @separator = response.get_tlv_value(TLV_TYPE_STRING)
                rescue RequestError
                  @separator = '\\'
                end

                return @separator
              end

              class << self
                alias Separator separator
                alias SEPARATOR separator
              end

              #
              # Search for files matching +glob+ starting in directory +root+.
              #
              # Returns an Array (possibly empty) of Hashes. Each element has the following
              # keys:
              # 'path'::  The directory in which the file was found
              # 'name'::  File name
              # 'size'::  Size of the file, in bytes
              #
              # Example:
              #    client.fs.file.search(client.fs.dir.pwd, "*.txt")
              #    # => [{"path"=>"C:\\Documents and Settings\\user\\Desktop", "name"=>"foo.txt", "size"=>0}]
              #
              # Raises a RequestError if +root+ is not a directory.
              #
              def self.search(root = nil, glob = '*.*', recurse = true, timeout = -1, modified_start_date = nil, modified_end_date = nil)
                files = ::Array.new

                request = Packet.create_request(COMMAND_ID_STDAPI_FS_SEARCH)

                root = client.unicode_filter_decode(root) if root
                root = root.chomp(separator) if root && !root.eql?('/')

                request.add_tlv(TLV_TYPE_SEARCH_ROOT, root)
                request.add_tlv(TLV_TYPE_SEARCH_GLOB, glob)
                request.add_tlv(TLV_TYPE_SEARCH_RECURSE, recurse)
                request.add_tlv(TLV_TYPE_SEARCH_M_START_DATE, modified_start_date) if modified_start_date
                request.add_tlv(TLV_TYPE_SEARCH_M_END_DATE, modified_end_date) if modified_end_date

                # we set the response timeout to -1 to wait indefinitely as a
                # search could take an indeterminate amount of time to complete.
                response = client.send_request(request, timeout)
                if (response.result == 0)
                  response.each(TLV_TYPE_SEARCH_RESULTS) do |results|
                    files << {
                      'path' => client.unicode_filter_encode(results.get_tlv_value(TLV_TYPE_FILE_PATH).chomp(separator)),
                      'name' => client.unicode_filter_encode(results.get_tlv_value(TLV_TYPE_FILE_NAME)),
                      'size' => results.get_tlv_value(TLV_TYPE_FILE_SIZE),
                      'mtime' => results.get_tlv_value(TLV_TYPE_SEARCH_MTIME)
                    }
                  end
                end

                return files
              end

              #
              # Returns the base name of the supplied file path to the caller.
              #
              def self.basename(*a)
                path = a[0]

                # Allow both kinds of dir serparators since lots and lots of code
                # assumes one or the other so this ends up getting called with strings
                # like: "C:\\foo/bar"
                path =~ %r{.*[/\\](.*)$}

                Rex::FileUtils.clean_path(::Regexp.last_match(1) || path)
              end

              #
              # Expands a file path, substituting all environment variables, such as
              # %TEMP% on Windows or $HOME on Unix
              #
              # Examples:
              #    client.fs.file.expand_path("%appdata%")
              #    # => "C:\\Documents and Settings\\user\\Application Data"
              #    client.fs.file.expand_path("~")
              #    # => "/home/user"
              #    client.fs.file.expand_path("$HOME/dir")
              #    # => "/home/user/dir"
              #    client.fs.file.expand_path("asdf")
              #    # => "asdf"
              #
              def self.expand_path(path)
                case client.platform
                when 'osx', 'freebsd', 'bsd', 'linux', 'android', 'apple_ios'
                  # For unix-based systems, do some of the work here
                  # First check for ~
                  path_components = path.split(separator)
                  if path_components.length > 0 && path_components[0] == '~'
                    path = "$HOME#{path[1..-1]}"
                  end

                  # Now find the environment variables we'll need from the client
                  env_regex = /\$(?:([A-Za-z0-9_]+)|\{([A-Za-z0-9_]+)\})/
                  matches = path.to_enum(:scan, env_regex).map { Regexp.last_match }
                  env_vars = matches.map { |match| (match[1] || match[2]).to_s }.uniq

                  # Retrieve them
                  env_vals = client.sys.config.getenvs(*env_vars)

                  # Now fill them in
                  path.gsub(env_regex) do |_z|
                    envvar = ::Regexp.last_match(1)
                    envvar = ::Regexp.last_match(2) if envvar.nil?
                    env_vals[envvar]
                  end
                else
                  request = Packet.create_request(COMMAND_ID_STDAPI_FS_FILE_EXPAND_PATH)

                  request.add_tlv(TLV_TYPE_FILE_PATH, client.unicode_filter_decode(path))

                  response = client.send_request(request)

                  return client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_FILE_PATH))
                end
              end

              #
              # Calculates the MD5 (16-bytes raw) of a remote file
              #
              def self.md5(path)
                request = Packet.create_request(COMMAND_ID_STDAPI_FS_MD5)

                request.add_tlv(TLV_TYPE_FILE_PATH, client.unicode_filter_decode(path))

                response = client.send_request(request)

                # older meterpreter binaries will send FILE_NAME containing the hash
                hash = response.get_tlv_value(TLV_TYPE_FILE_HASH) ||
                       response.get_tlv_value(TLV_TYPE_FILE_NAME)
                return hash
              end

              #
              # Calculates the SHA1 (20-bytes raw) of a remote file
              #
              def self.sha1(path)
                request = Packet.create_request(COMMAND_ID_STDAPI_FS_SHA1)

                request.add_tlv(TLV_TYPE_FILE_PATH, client.unicode_filter_decode(path))

                response = client.send_request(request)

                # older meterpreter binaries will send FILE_NAME containing the hash
                hash = response.get_tlv_value(TLV_TYPE_FILE_HASH) ||
                       response.get_tlv_value(TLV_TYPE_FILE_NAME)
                return hash
              end

              #
              # Performs a stat on a file and returns a FileStat instance.
              #
              def self.stat(name)
                return client.fs.filestat.new(name)
              end

              #
              # Returns true if the remote file +name+ exists, false otherwise
              #
              def self.exist?(name)
                r = begin
                  client.fs.filestat.new(name)
                rescue StandardError
                  nil
                end
                r ? true : false
              end

              #
              # Performs a delete on the remote file +name+
              #
              def self.rm(name)
                request = Packet.create_request(COMMAND_ID_STDAPI_FS_DELETE_FILE)

                request.add_tlv(TLV_TYPE_FILE_PATH, client.unicode_filter_decode(name))

                response = client.send_request(request)

                return response
              end

              class << self
                alias unlink rm
                alias delete rm
              end

              #
              # Performs a rename from oldname to newname
              #
              def self.mv(oldname, newname)
                request = Packet.create_request(COMMAND_ID_STDAPI_FS_FILE_MOVE)

                request.add_tlv(TLV_TYPE_FILE_NAME, client.unicode_filter_decode(oldname))
                request.add_tlv(TLV_TYPE_FILE_PATH, client.unicode_filter_decode(newname))

                response = client.send_request(request)

                return response
              end

              class << self
                alias move mv
                alias rename mv
              end

              #
              # Performs a copy from oldname to newname
              #
              def self.cp(oldname, newname)
                request = Packet.create_request(COMMAND_ID_STDAPI_FS_FILE_COPY)

                request.add_tlv(TLV_TYPE_FILE_NAME, client.unicode_filter_decode(oldname))
                request.add_tlv(TLV_TYPE_FILE_PATH, client.unicode_filter_decode(newname))

                response = client.send_request(request)

                return response
              end

              class << self
                alias copy cp
              end

              #
              # Performs a chmod on the remote file
              #
              def self.chmod(name, mode)
                request = Packet.create_request(COMMAND_ID_STDAPI_FS_CHMOD)

                request.add_tlv(TLV_TYPE_FILE_PATH, client.unicode_filter_decode(name))
                request.add_tlv(TLV_TYPE_FILE_MODE_T, mode)

                response = client.send_request(request)

                return response
              end

              #
              # Upload one or more files to the remote remote directory supplied in
              # +destination+.
              #
              # If a block is given, it will be called before each file is uploaded and
              # again when each upload is complete.
              #
              def self.upload(dest, *src_files, &stat)
                src_files.each do |src|
                  if (basename(dest) != ::File.basename(src))
                    dest += separator unless dest.end_with?(separator)
                    dest += ::File.basename(src)
                  end
                  stat.call('Uploading', src, dest) if stat

                  upload_file(dest, src)
                  stat.call(STEP_COMPLETED, src, dest) if stat
                end
              end

              #
              # Upload a single file.
              #
              def self.upload_file(dest_file, src_file, &stat)
                # Open the file on the remote side for writing and read
                # all of the contents of the local file
                stat.call('Uploading', src_file, dest_file) if stat
                dest_fd = nil
                src_fd = nil
                buf_size = 8 * 1024 * 1024

                begin
                  dest_fd = client.fs.file.new(dest_file, 'wb')
                  src_fd = ::File.open(src_file, 'rb')
                  src_size = src_fd.stat.size
                  while (buf = src_fd.read(buf_size))
                    dest_fd.write(buf)
                    percent = dest_fd.pos.to_f / src_size.to_f * 100.0
                    msg = "Uploaded #{Filesize.new(dest_fd.pos).pretty} of " \
                      "#{Filesize.new(src_size).pretty} (#{percent.round(2)}%)"
                    stat.call(msg, src_file, dest_file) if stat
                  end
                ensure
                  src_fd.close unless src_fd.nil?
                  dest_fd.close unless dest_fd.nil?
                end
                stat.call(STEP_COMPLETED, src_file, dest_file) if stat
              end

              def self.is_glob?(name)
                /\*|\[|\?/ === name
              end

              #
              # Download one or more files from the remote computer to the local
              # directory supplied in destination.
              #
              # If a block is given, it will be called before each file is downloaded and
              # again when each download is complete.
              #
              def self.download(dest, src_files, opts = {}, &stat)
                dest.force_encoding('UTF-8')
                timestamp = opts['timestamp']
                [*src_files].each do |src|
                  src.force_encoding('UTF-8')
                  if (::File.basename(dest) != File.basename(src))
                    # The destination when downloading is a local file so use this
                    # system's separator
                    dest += ::File::SEPARATOR unless dest.end_with?(::File::SEPARATOR)
                    dest += File.basename(src)
                  end

                  # XXX: dest can be the same object as src, so we use += instead of <<
                  if timestamp
                    dest += timestamp
                  end

                  stat.call('Downloading', src, dest) if stat
                  result = download_file(dest, src, opts, &stat)
                  stat.call(result, src, dest) if stat
                end
              end

              #
              # Download a single file.
              #
              def self.download_file(dest_file, src_file, opts = {}, &stat)
                stat ||= ->(a, b, c) {}

                adaptive = opts['adaptive']
                block_size = opts['block_size'] || 1024 * 1024
                continue = opts['continue']
                tries_no = opts['tries_no']
                tries = opts['tries']
                force_overwrite = opts['force_overwrite'] || false
                overwrite_existing = false
                src_fd = client.fs.file.new(src_file, 'rb')

                # Check for changes
                src_stat = client.fs.filestat.new(src_file)
                if ::File.exist?(dest_file)
                  dst_stat = ::File.stat(dest_file)
                  if src_stat.size == dst_stat.size && src_stat.mtime == dst_stat.mtime
                    src_fd.close
                    return STEP_SKIPPED
                  end
                  if !force_overwrite
                    src_fd.close
                    return STEP_SKIPPED_WOULD_OVERWRITE
                  else
                    overwrite_existing = true
                  end
                end

                # Make the destination path if necessary
                dir = ::File.dirname(dest_file)
                ::FileUtils.mkdir_p(dir) if dir and !::File.directory?(dir)

                src_size = Filesize.new(src_stat.size).pretty

                if continue
                  # continue downloading the file - skip downloaded part in the source
                  dst_fd = ::File.new(dest_file, 'ab')
                  begin
                    dst_fd.seek(0, ::IO::SEEK_END)
                    in_pos = dst_fd.pos
                    src_fd.seek(in_pos)
                    stat.call("Continuing from #{Filesize.new(in_pos).pretty} of #{src_size}", src_file, dest_file)
                  rescue StandardError
                    # if we can't seek, download again
                    stat.call('Error continuing - downloading from scratch', src_file, dest_file)
                    dst_fd.close
                    dst_fd = ::File.new(dest_file, 'wb')
                  end
                else
                  dst_fd = ::File.new(dest_file, 'wb')
                end

                # Keep transferring until EOF is reached...
                begin
                  if tries
                    # resume when timeouts encountered
                    seek_back = false
                    adjust_block = false
                    tries_cnt = 0
                    begin # while
                      begin # exception
                        if seek_back
                          in_pos = dst_fd.pos
                          src_fd.seek(in_pos)
                          seek_back = false
                          stat.call("Resuming at #{Filesize.new(in_pos).pretty} of #{src_size}", src_file, dest_file)
                        else
                          # successfully read and wrote - reset the counter
                          tries_cnt = 0
                        end
                        adjust_block = true
                        data = src_fd.read(block_size)
                        adjust_block = false
                      rescue Rex::TimeoutError
                        # timeout encountered - either seek back and retry or quit
                        if (tries && (tries_no == 0 || tries_cnt < tries_no))
                          tries_cnt += 1
                          seek_back = true
                          # try a smaller block size for the next round
                          if adaptive && adjust_block
                            block_size = [block_size >> 1, MIN_BLOCK_SIZE].max
                            adjust_block = false
                            msg = "Error downloading, block size set to #{block_size} - retry # #{tries_cnt}"
                            stat.call(msg, src_file, dest_file)
                          else
                            stat.call("Error downloading - retry # #{tries_cnt}", src_file, dest_file)
                          end
                          retry
                        else
                          stat.call('Error downloading - giving up', src_file, dest_file)
                          raise
                        end
                      end
                      dst_fd.write(data) if !data.nil?
                      percent = dst_fd.pos.to_f / src_stat.size.to_f * 100.0
                      msg = "Downloaded #{Filesize.new(dst_fd.pos).pretty} of #{src_size} (#{percent.round(2)}%)"
                      stat.call(msg, src_file, dest_file)
                    end while (!data.nil?)
                  else
                    # do the simple copying quitting on the first error
                    while ((data = src_fd.read(block_size)) != nil)
                      dst_fd.write(data)
                      percent = dst_fd.pos.to_f / src_stat.size.to_f * 100.0
                      msg = "Downloaded #{Filesize.new(dst_fd.pos).pretty} of #{src_size} (#{percent.round(2)}%)"
                      stat.call(msg, src_file, dest_file)
                    end
                  end
                rescue EOFError
                ensure
                  src_fd.close
                  dst_fd.close
                end

                # Clone the times from the remote file
                ::File.utime(src_stat.atime, src_stat.mtime, dest_file)
                return overwrite_existing ? STEP_COMPLETED_OVERWRITTEN : STEP_COMPLETED
              end

              #
              # With no associated block, File.open is a synonym for ::new. If the optional
              # code block is given, it will be passed the opened file as an argument, and
              # the File object will automatically be closed when the block terminates. In
              # this instance, File.open returns the value of the block.
              #
              # (doc stolen from http://www.ruby-doc.org/core-1.9.3/File.html#method-c-open)
              #
              def self.open(name, mode = 'r', perms = 0)
                f = new(name, mode, perms)
                if block_given?
                  ret = yield f
                  f.close
                  return ret
                else
                  return f
                end
              end

              ##
              #
              # Constructor
              #
              ##

              #
              # Initializes and opens the specified file with the specified permissions.
              #
              def initialize(name, mode = 'r', perms = 0)
                self.client = self.class.client
                self.filed = _open(name, mode, perms)
              end

              ##
              #
              # IO implementers
              #
              ##

              #
              # Returns whether or not the file has reach EOF.
              #
              def eof
                return filed.eof
              end

              #
              # Returns the current position of the file pointer.
              #
              def pos
                return filed.tell
              end

              #
              # Synonym for sysseek.
              #
              def seek(offset, whence = ::IO::SEEK_SET)
                return sysseek(offset, whence)
              end

              #
              # Seeks to the supplied offset based on the supplied relativity.
              #
              def sysseek(offset, whence = ::IO::SEEK_SET)
                return filed.seek(offset, whence)
              end

              protected

              ##
              #
              # Internal methods
              #
              ##

              #
              # Creates a File channel using the supplied information.
              #
              def _open(name, mode = 'r', perms = 0)
                return Rex::Post::Meterpreter::Channels::Pools::File.open(
                  client, name, mode, perms
                )
              end

              attr_accessor :client # :nodoc:

            end
          end; end; end; end; end; end
