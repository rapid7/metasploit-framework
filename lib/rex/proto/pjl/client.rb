# https://en.wikipedia.org/wiki/Printer_Job_Language
# See external links for PJL spec

module Rex::Proto::PJL
class Client

  def initialize(sock)
    @sock = sock
  end

  # Begin PJL job
  #
  # @return [void]
  def begin_job
    command = "#{UEL}#{PREFIX}\n"
    @sock.put(command)
  end

  # End PJL job
  #
  # @return [void]
  def end_job
    command = UEL
    @sock.put(command)
  end

  # Send INFO request and read response
  #
  # @param category [String] INFO category
  # @return [String] INFO response
  def info(category)
    categories = {
      :id => INFO_ID,
      :status => INFO_STATUS,
      :filesys => INFO_FILESYS
    }
    unless categories.has_key?(category)
      raise ArgumentError, "Unknown INFO category"
    end
    command = "#{categories[category]}\n"
    begin_job
    @sock.put(command)
    end_job
    @sock.get
  end

  # Get version information
  #
  # @return [String] Version information
  def info_id
    id = nil
    response = info(:id)
    if response =~ /"(.*?)"/m
      id = $1
    end
    return id
  end

  # List volumes
  #
  # @return [String] Volume listing
  def info_filesys
    filesys = nil
    response = info(:filesys)
    if response =~ /\[\d+ TABLE\]\r?\n(.*?)\f/m
      filesys = $1
    end
    return filesys
  end

  # Get ready message
  #
  # @return [String] Ready message
  def get_rdymsg
    rdymsg = nil
    response = info(:status)
    if response =~ /DISPLAY="(.*?)"/m
      rdymsg = $1
    end
    return rdymsg
  end

  # Set ready message
  #
  # @param message [String] Ready message
  # @return [void]
  def set_rdymsg(message)
    command = %Q{#{RDYMSG_DISPLAY} = "#{message}"\n}
    begin_job
    @sock.put(command)
    end_job
  end

  # Initialize volume
  #
  # @param volume [String] Volume
  # @return [void]
  def fsinit(volume)
    if volume !~ /^[0-2]:$/
      raise ArgumentError, "Volume must be 0:, 1:, or 2:"
    end
    command = %Q{#{FSINIT_VOLUME} = "#{volume}"\n}
    begin_job
    @sock.put(command)
    end_job
  end

  # List directory
  #
  # @param pathname [String] Pathname
  # @param count [Fixnum] Number of entries to list
  # @return [String] Directory listing
  def fsdirlist(pathname, count = COUNT_MAX)
    if pathname !~ /^[0-2]:/
      raise ArgumentError, "Pathname must begin with 0:, 1:, or 2:"
    end
    listing = nil
    command = %Q{#{FSDIRLIST_NAME} = "#{pathname}" ENTRY=1 COUNT=#{count}\n}
    begin_job
    @sock.put(command)
    end_job
    response = @sock.get
    if response =~ /ENTRY=1\r?\n(.*?)\f/m
      listing = $1
    end
    return listing
  end

  # Download file
  #
  # @param pathname [String] Pathname
  # @param size [Fixnum] Size of file
  # @return [String] File as a string
  def fsupload(pathname, size = SIZE_MAX)
    if pathname !~ /^[0-2]:/
      raise ArgumentError, "Pathname must begin with 0:, 1:, or 2:"
    end
    file = nil
    command = %Q{#{FSUPLOAD_NAME} = "#{pathname}" OFFSET=0 SIZE=#{size}\n}
    begin_job
    @sock.put(command)
    end_job
    response = @sock.get
    if response =~ /SIZE=\d+\r?\n(.*?)\f/m
      file = $1
    end
    return file
  end

end
end
