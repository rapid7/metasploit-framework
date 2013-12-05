module Rex
module Proto
module PJL

class Client

  def initialize(sock)
    @sock = sock
  end

  def pjl_begin_job
    command = "#{PJL_UEL}#{PJL_PREFIX}\n"
    @sock.put(command)
  end

  def pjl_end_job
    command = "#{PJL_UEL}\n"
    @sock.put(command)
  end

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

  def pjl_get_info_id
    id = nil
    response = pjl_get_info(:id)
    if response =~ /"(.*)"/
      id = $1
    end
    return id
  end

  def pjl_get_rdymsg
    rdymsg = nil
    response = pjl_get_info(:status)
    if response =~ /DISPLAY="(.*)"/
      rdymsg = $1
    end
    return rdymsg
  end

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
