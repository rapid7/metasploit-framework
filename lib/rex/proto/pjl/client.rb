# -*- coding: binary -*-

# https://en.wikipedia.org/wiki/Printer_Job_Language
# See external links for PJL spec

module Rex::Proto::PJL
class Client

  def initialize(sock)
    @sock = sock
  end

  # Begin a PJL job
  #
  # @return [void]
  def begin_job
    @sock.put("#{UEL}#{PREFIX}\n")
  end

  # End a PJL job
  #
  # @return [void]
  def end_job
    @sock.put(UEL)
  end

  # Send an INFO request and read the response
  #
  # @param category [String] INFO category
  # @return [String] INFO response
  def info(category)
    categories = {
      :id => Info::ID,
      :status => Info::STATUS,
      :variables => Info::VARIABLES,
      :filesys => Info::FILESYS
    }

    unless categories.has_key?(category)
      raise ArgumentError, "Unknown INFO category"
    end

    @sock.put("#{categories[category]}\n")
    @sock.get(DEFAULT_TIMEOUT)
  end

  # Get version information
  #
  # @return [String] Version information
  def info_id
    id = nil

    if info(:id) =~ /"(.*?)"/m
      id = $1
    end

    id
  end

  # Get environment variables
  #
  # @return [String] Environment variables
  def info_variables
    env_vars = nil

    if info(:variables) =~ /#{Info::VARIABLES}\r?\n(.*?)\f/m
      env_vars = $1
    end

    env_vars
  end

  # List volumes
  #
  # @return [String] Volume listing
  def info_filesys
    filesys = nil

    if info(:filesys) =~ /\[\d+ TABLE\]\r?\n(.*?)\f/m
      filesys = $1
    end

    filesys
  end

  # Get the ready message
  #
  # @return [String] Ready message
  def get_rdymsg
    rdymsg = nil

    if info(:status) =~ /DISPLAY="(.*?)"/m
      rdymsg = $1
    end

    rdymsg
  end

  # Set the ready message
  #
  # @param message [String] Ready message
  # @return [void]
  def set_rdymsg(message)
    @sock.put(%Q{#{RDYMSG} DISPLAY = "#{message}"\n})
  end

  # Initialize a volume
  #
  # @param volume [String] Volume
  # @return [void]
  def fsinit(volume)
    if volume !~ /^[0-2]:$/
      raise ArgumentError, "Volume must be 0:, 1:, or 2:"
    end

    @sock.put(%Q{#{FSINIT} VOLUME = "#{volume}"\n})
  end

  # Query a file
  #
  # @param path [String] Remote path
  # @return [Boolean] True if file exists
  def fsquery(path)
    if path !~ /^[0-2]:/
      raise ArgumentError, "Path must begin with 0:, 1:, or 2:"
    end

    file = false

    @sock.put(%Q{#{FSQUERY} NAME = "#{path}"\n})

    if @sock.get(DEFAULT_TIMEOUT) =~ /TYPE=(FILE|DIR)/m
      file = true
    end

    file
  end

  # List a directory
  #
  # @param path [String] Remote path
  # @param count [Integer] Number of entries to list
  # @return [String] Directory listing
  def fsdirlist(path, count = COUNT_MAX)
    if path !~ /^[0-2]:/
      raise ArgumentError, "Path must begin with 0:, 1:, or 2:"
    end

    listing = nil

    @sock.put(%Q{#{FSDIRLIST} NAME = "#{path}" ENTRY=1 COUNT=#{count}\n})

    if @sock.get(DEFAULT_TIMEOUT) =~ /ENTRY=1\r?\n(.*?)\f/m
      listing = $1
    end

    listing
  end

  # Download a file
  #
  # @param path [String] Remote path
  # @return [String] File as a string
  def fsupload(path)
    if path !~ /^[0-2]:/
      raise ArgumentError, "Path must begin with 0:, 1:, or 2:"
    end

    file = nil

    @sock.put(%Q{#{FSUPLOAD} NAME = "#{path}" OFFSET=0 SIZE=#{SIZE_MAX}\n})

    if @sock.get(DEFAULT_TIMEOUT) =~ /SIZE=\d+\r?\n(.*)\f/m
      file = $1
    end

    file
  end

  # Upload a file or write string data to remote path
  #
  # @param data_or_lpath [String] data or local path
  # @param rpath [String] Remote path
  # @param is_file [Boolean] True if data_or_lpath is a local file path
  # @return [Boolean] True if the file was uploaded
  def fsdownload(data_or_lpath, rpath, is_file: true)
    if rpath !~ /^[0-2]:/
      raise ArgumentError, "Path must begin with 0:, 1:, or 2:"
    end

    file = is_file ? File.read(data_or_lpath) : data_or_lpath

    @sock.put(
      %Q{#{FSDOWNLOAD} FORMAT:BINARY SIZE=#{file.length} NAME = "#{rpath}"\n}
    )

    @sock.put(file)
    @sock.put(UEL)

    fsquery(rpath)
  end

  # Delete a file
  #
  # @param path [String] Remote path
  # @return [Boolean] True if the file was deleted
  def fsdelete(path)
    if path !~ /^[0-2]:/
      raise ArgumentError, "Path must begin with 0:, 1:, or 2:"
    end

    @sock.put(%Q{#{FSDELETE} NAME = "#{path}"\n})

    !fsquery(path)
  end

end
end
