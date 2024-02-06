# -*- coding: binary -*-
require 'network_interface'

module Msf

###
#
# Local network address option.
#
###
class OptAddressLocal < OptAddress
  def interfaces
    begin
      NetworkInterface.interfaces || []
    rescue NetworkInterface::Error => e
      elog(e)
      []
    end
  end

  def normalize(value)
    return unless value.kind_of?(String)
    return value unless interfaces.include?(value)

    addrs = NetworkInterface.addresses(value).values.flatten

    # Strip interface name from address (see getifaddrs(3))
    addrs = addrs.map { |x| x['addr'].split('%').first }.select do |addr|
      begin
        IPAddr.new(addr)
      rescue IPAddr::Error
        false
      end
    end

    # Sort for deterministic normalization; preference ipv4 addresses followed by their value
    sorted_addrs = addrs.sort_by { |addr| ip_addr = IPAddr.new(addr); [ip_addr.ipv4? ? 0 : 1, ip_addr.to_i] }

    sorted_addrs.any? ? sorted_addrs.first : ''
  end

  def valid?(value, check_empty: true)
    return false if check_empty && empty_required_value?(value)
    return false unless value.kind_of?(String) || value.kind_of?(NilClass)

    return true if interfaces.include?(value)

    super
  end
end

end
