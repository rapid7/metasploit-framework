module Msf::DBManager::Validators
  def ipv46_validator(addr)
    ipv4_validator(addr) or ipv6_validator(addr)
  end

  def ipv4_validator(addr)
    return false unless addr.kind_of? String
    Rex::Socket.is_ipv4?(addr)
  end

  def ipv6_validator(addr)
    Rex::Socket.is_ipv6?(addr)
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