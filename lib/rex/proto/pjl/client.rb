#
# https://en.wikipedia.org/wiki/Printer_Job_Language
#
# See external links for PJL spec
#

module Rex
module Proto
module PJL

class Client

  def initialize(sock)
    @sock = sock
  end

  #
  # Begin PJL job
  #
  def pjl_begin_job
    command = "#{PJL_UEL}#{PJL_PREFIX}\n"
    @sock.put(command)
  end

  #
  # End PJL job
  #
  def pjl_end_job
    command = "#{PJL_UEL}\n"
    @sock.put(command)
  end

  #
  # Send INFO request and receive response
  #
  # @param category [String] INFO category
  # @return [String] INFO response
  #
  def pjl_get_info(category)
    case category
      when :id
        command = "#{PJL_INFO_ID}\n"
      when :status
        command = "#{PJL_INFO_STATUS}\n"
    end
    pjl_begin_job
    @sock.put(command)
    pjl_end_job
    @sock.get_once
  end

  #
  # Get version information
  #
  # @return [String] Version information
  #
  def pjl_get_info_id
    id = nil
    response = pjl_get_info(:id)
    if response =~ /"(.*)"/
      id = $1
    end
    return id
  end

  #
  # Get ready message
  #
  # @return [String] Ready message
  #
  def pjl_get_rdymsg
    rdymsg = nil
    response = pjl_get_info(:status)
    if response =~ /DISPLAY="(.*)"/
      rdymsg = $1
    end
    return rdymsg
  end

  #
  # Set ready message
  #
  # @param message [String] Ready message
  #
  def pjl_set_rdymsg(message)
    command = %Q{#{PJL_RDYMSG_DISPLAY} = "#{message}"\n}
    pjl_begin_job
    @sock.put(command)
    pjl_end_job
  end

end
end
end
end
