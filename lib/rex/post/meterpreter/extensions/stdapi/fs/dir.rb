# -*- coding: binary -*-

require 'rex/post/dir'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Fs

###
#
# This class implements directory operations against the remote endpoint.  It
# implements the Rex::Post::Dir interface.
#
###
class Dir < Rex::Post::Dir

  class << self
    attr_accessor :client
  end

  ##
  #
  # Constructor
  #
  ##

  #
  # Initializes the directory instance.
  #
  def initialize(path)
    self.path   = path
    self.client = self.class.client
  end

  ##
  #
  # Enumeration
  #
  ##

  #
  # Enumerates all of the contents of the directory.
  #
  def each(&block)
    client.fs.dir.foreach(self.path, &block)
  end

  #
  # Enumerates all of the files/folders in a given directory.
  #
  def Dir.entries(name = getwd, glob = nil)
    request = Packet.create_request('stdapi_fs_ls')
    files   = []
    name = name + ::File::SEPARATOR + glob if glob

    request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode(name))

    response = client.send_request(request)

    response.each(TLV_TYPE_FILE_NAME) { |file_name|
      files << client.unicode_filter_encode(file_name.value)
    }

    return files
  end

  #
  # Enumerates files with a bit more information than the default entries.
  #
  def Dir.entries_with_info(name = getwd)
    request = Packet.create_request('stdapi_fs_ls')
    files = []
    sbuf = nil
    new_stat_buf = true

    request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode(name))

    response = client.send_request(request)

    fname = response.get_tlvs(TLV_TYPE_FILE_NAME)
    fsname = response.get_tlvs(TLV_TYPE_FILE_SHORT_NAME)
    fpath = response.get_tlvs(TLV_TYPE_FILE_PATH)

    if response.has_tlv?(TLV_TYPE_STAT_BUF)
      sbuf = response.get_tlvs(TLV_TYPE_STAT_BUF)
    else
      sbuf = response.get_tlvs(TLV_TYPE_STAT_BUF32)
      new_stat_buf = false
    end

    if (!fname or !sbuf)
      return []
    end

    fname.each_with_index { |file_name, idx|
      st = nil

      if (sbuf[idx])
        st = ::Rex::Post::FileStat.new
        if new_stat_buf
          st.update(sbuf[idx].value)
        else
          st.update32(sbuf[idx].value)
        end
      end

      files <<
        {
          'FileName' => client.unicode_filter_encode(file_name.value),
          'FilePath' => client.unicode_filter_encode(fpath[idx].value),
          'FileShortName' => fsname[idx] ? fsname[idx].value : nil,
          'StatBuf'  => st,
        }
    }

    return files
  end

  #
  # Enumerates all of the files and folders matched with name.
  # When option dir is true, return matched folders.
  #
  def Dir.match(name, dir = false)
    path  = name + '*'
    files = []
    sbuf = nil
    new_stat_buf = true

    request = Packet.create_request('stdapi_fs_ls')
    request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode(path))
    response = client.send_request(request)

    fpath = response.get_tlvs(TLV_TYPE_FILE_PATH)

    if response.has_tlv?(TLV_TYPE_STAT_BUF)
      sbuf = response.get_tlvs(TLV_TYPE_STAT_BUF)
    else
      sbuf = response.get_tlvs(TLV_TYPE_STAT_BUF32)
      new_stat_buf = false
    end

    unless fpath && sbuf
      return []
    end

    fpath.each_with_index do |file_name, idx|
      if dir && sbuf[idx]
        st = ::Rex::Post::FileStat.new
        if new_stat_buf
          st.update(sbuf[idx].value)
        else
          st.update32(sbuf[idx].value)
        end
        next if st.ftype != 'directory' # if file_name isn't directory
      end

      if !file_name.value.end_with?('.', '\\', '/') # Exclude current and parent directory
        files << client.unicode_filter_encode(file_name.value)
      end
    end

    files
  end

  ##
  #
  # General directory operations
  #
  ##

  #
  # Changes the working directory of the remote process.
  #
  def Dir.chdir(path)
    request = Packet.create_request('stdapi_fs_chdir')

    request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode( path ))

    response = client.send_request(request)

    return 0
  end

  #
  # Creates a directory.
  #
  def Dir.mkdir(path)
    request = Packet.create_request('stdapi_fs_mkdir')

    request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode( path ))

    response = client.send_request(request)

    return 0
  end

  #
  # Returns the current working directory of the remote process.
  #
  def Dir.pwd
    request = Packet.create_request('stdapi_fs_getwd')

    response = client.send_request(request)

    return client.unicode_filter_encode(response.get_tlv(TLV_TYPE_DIRECTORY_PATH).value)
  end

  #
  # Synonym for pwd.
  #
  def Dir.getwd
    pwd
  end

  #
  # Removes the supplied directory if it's empty.
  #
  def Dir.delete(path)
    request = Packet.create_request('stdapi_fs_delete_dir')

    request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode( path ))

    response = client.send_request(request)

    return 0
  end

  #
  # Synonyms for delete.
  #
  def Dir.rmdir(path)
    delete(path)
  end

  #
  # Synonyms for delete.
  #
  def Dir.unlink(path)
    delete(path)
  end

  ##
  #
  # Directory mirroring
  #
  ##

  #
  # Downloads the contents of a remote directory a
  # local directory, optionally in a recursive fashion.
  #
  def Dir.download(dst, src, opts = {}, force = true, glob = nil, &stat)
    tries_cnt = 0

    continue =  opts["continue"]
    recursive = opts["recursive"]
    timestamp = opts["timestamp"]
    tries_no = opts["tries_no"] || 0
    tries = opts["tries"]

    begin
      dir_files = self.entries(src, glob)
    rescue Rex::TimeoutError
      if (tries && (tries_no == 0 || tries_cnt < tries_no))
        tries_cnt += 1
        stat.call('error listing  - retry #', tries_cnt, src) if (stat)
        retry
      else
        stat.call('error listing directory - giving up', src, dst) if (stat)
        raise
      end
    end

    dir_files.each { |src_sub|
      dst_sub = src_sub.dup
      dst_sub.gsub!(::File::SEPARATOR, '_')                                   # '/' on all systems
      dst_sub.gsub!(::File::ALT_SEPARATOR, '_') if ::File::ALT_SEPARATOR      # nil on Linux, '\' on Windows

      dst_item = ::File.join(dst, client.unicode_filter_encode(dst_sub))
      src_item = src + client.fs.file.separator + client.unicode_filter_encode(src_sub)

      if (src_sub == '.' or src_sub == '..')
        next
      end

      tries_cnt = 0
      begin
        src_stat = client.fs.filestat.new(src_item)
      rescue Rex::TimeoutError
        if (tries && (tries_no == 0 || tries_cnt < tries_no))
          tries_cnt += 1
          stat.call('error opening file - retry #', tries_cnt, src_item) if (stat)
          retry
        else
          stat.call('error opening file - giving up', tries_cnt, src_item) if (stat)
          raise
        end
      end

      if (src_stat.file?)
        if timestamp
          dst_item << timestamp
        end

        stat.call('downloading', src_item, dst_item) if (stat)

        begin
          if (continue || tries)  # allow to file.download to log messages
            result = client.fs.file.download_file(dst_item, src_item, opts, &stat)
          else
            result = client.fs.file.download_file(dst_item, src_item, opts)
          end
          stat.call(result, src_item, dst_item) if (stat)
        rescue ::Rex::Post::Meterpreter::RequestError => e
          if force
            stat.call('failed', src_item, dst_item) if (stat)
          else
            raise e
          end
        end

      elsif (src_stat.directory?)
        if (recursive == false)
          next
        end

        begin
          ::Dir.mkdir(dst_item)
        rescue
        end

        stat.call('mirroring', src_item, dst_item) if (stat)
        download(dst_item, src_item, opts, force, glob, &stat)
        stat.call('mirrored', src_item, dst_item) if (stat)
      end
    } # entries
  end

  #
  # Uploads the contents of a local directory to a remote
  # directory, optionally in a recursive fashion.
  #
  def Dir.upload(dst, src, recursive = false, &stat)
    ::Dir.entries(src).each { |src_sub|
      dst_item = dst + client.fs.file.separator + client.unicode_filter_encode(src_sub)
      src_item = src + ::File::SEPARATOR + client.unicode_filter_encode(src_sub)

      if (src_sub == '.' or src_sub == '..')
        next
      end

      src_stat = ::File.stat(src_item)

      if (src_stat.file?)
        stat.call('uploading', src_item, dst_item) if (stat)
        client.fs.file.upload(dst_item, src_item)
        stat.call('uploaded', src_item, dst_item) if (stat)
      elsif (src_stat.directory?)
        if (recursive == false)
          next
        end

        begin
          self.mkdir(dst_item)
        rescue
        end

        stat.call('mirroring', src_item, dst_item) if (stat)
        upload(dst_item, src_item, recursive, &stat)
        stat.call('mirrored', src_item, dst_item) if (stat)
      end
    }
  end

  #
  # The path of the directory that was opened.
  #
  attr_reader   :path
protected
  attr_accessor :client # :nodoc:
  attr_writer   :path # :nodoc:

end

end; end; end; end; end; end

