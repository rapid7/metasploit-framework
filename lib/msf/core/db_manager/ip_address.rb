module Msf::DBManager::IPAddress
  def ipv46_validator(addr)
    ipv4_validator(addr) or ipv6_validator(addr)
  end

  def ipv4_validator(addr)
    if addr.try(:ipv4?)
      true
    elsif addr.kind_of? String
      Rex::Socket.is_ipv4?(addr)
    else
      false
    end    
  end

  def ipv6_validator(addr)
    if addr.try(:ipv6?)
      true
    elsif addr.kind_of? String
      Rex::Socket.is_ipv6?(addr)
    else
      false
    end    
  end

  def rfc3330_reserved(ip)
    case ip
    when PacketFu::Octets
      ip_x = ip.to_x
      ip_i = ip.to_i
    when String
      if ipv46_validator(ip)
        ip_x = ip
        ip_i = Rex::Socket.addr_atoi(ip)
      else
        raise ArgumentError, "Invalid IP address: #{ip.inspect}"
      end
    when Integer
      if (0..2**32-1).include? ip
        ip_x = Rex::Socket.addr_itoa(ip)
        ip_i = ip
      else
        raise ArgumentError, "Invalid IP address: #{ip.inspect}"
      end
    else
      raise ArgumentError, "Invalid IP address: #{ip.inspect}"
    end
    return true if Rex::Socket::RangeWalker.new("0.0.0.0-0.255.255.255").include? ip_x
    return true if Rex::Socket::RangeWalker.new("127.0.0.0-127.255.255.255").include? ip_x
    return true if Rex::Socket::RangeWalker.new("169.254.0.0-169.254.255.255").include? ip_x
    return true if Rex::Socket::RangeWalker.new("224.0.0.0-239.255.255.255").include? ip_x
    return true if Rex::Socket::RangeWalker.new("255.255.255.255-255.255.255.255").include? ip_x
    return false
  end

  # Takes a space-delimited set of ips and ranges, and subjects
  # them to RangeWalker for validation. Returns true or false.
  def validate_ips(ips)
    ret = true
    begin
      ips.split(/\s+/).each {|ip|
        unless Rex::Socket::RangeWalker.new(ip).ranges
          ret = false
          break
        end
        }
    rescue
      ret = false
    end
    return ret
  end
end
