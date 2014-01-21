# https://en.wikipedia.org/wiki/Printer_Job_Language
# See external links for PJL spec

module Rex::Proto::PJL
class Client

  attr_reader :sock

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

  # List a directory
  #
  # @param pathname [String] Pathname
  # @param count [Fixnum] Number of entries to list
  # @return [String] Directory listing
  def fsdirlist(pathname, count = COUNT_MAX)
    if pathname !~ /^[0-2]:/
      raise ArgumentError, "Pathname must begin with 0:, 1:, or 2:"
    end

    listing = nil

    @sock.put(%Q{#{FSDIRLIST} NAME = "#{pathname}" ENTRY=1 COUNT=#{count}\n})

    if @sock.get(DEFAULT_TIMEOUT) =~ /ENTRY=1\r?\n(.*?)\f/m
      listing = $1
    end

    listing
  end

  # Download a file
  #
  # @param pathname [String] Pathname
  # @param size [Fixnum] Size of file
  # @return [String] File as a string
  def fsupload(pathname, size = SIZE_MAX)
    if pathname !~ /^[0-2]:/
      raise ArgumentError, "Pathname must begin with 0:, 1:, or 2:"
    end

    file = nil

    @sock.put(%Q{#{FSUPLOAD} NAME = "#{pathname}" OFFSET=0 SIZE=#{size}\n})

    if @sock.get(DEFAULT_TIMEOUT) =~ /SIZE=\d+\r?\n(.*)\f/m
      file = $1
    end

    file
  end

end
end
