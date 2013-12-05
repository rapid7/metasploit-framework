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
    command = "#{UEL}\n"
    @sock.put(command)
  end

  # Send INFO request and receive response
  #
  # @param category [String] INFO category
  # @return [String] INFO response
  def get_info(category)
    case category
    when :id
      command = "#{INFO_ID}\n"
    when :status
      command = "#{INFO_STATUS}\n"
    end
    begin_job
    @sock.put(command)
    end_job
    @sock.get_once
  end

  # Get version information
  #
  # @return [String] Version information
  def get_info_id
    id = nil
    response = get_info(:id)
    if response =~ /"(.*)"/
      id = $1
    end
    return id
  end

  # Get ready message
  #
  # @return [String] Ready message
  def get_rdymsg
    rdymsg = nil
    response = get_info(:status)
    if response =~ /DISPLAY="(.*)"/
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

end
end
