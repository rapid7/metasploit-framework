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
    NetworkInterface.interfaces || []
  end

  def normalize(value)
    return unless value.kind_of?(String)
    return value unless interfaces.include?(value)

    addrs = NetworkInterface.addresses(value).values.flatten

    # Strip interface name from address (see getifaddrs(3))
    addrs = addrs.map { |x| x['addr'].split('%').first }.select do |addr|
      begin
        IPAddr.new(addr)
      rescue IPAddr::InvalidAddressError
        false
      end
    end

    addrs.any? ? addrs.first : ''
  end

  def valid?(value, check_empty: true)
    return false if check_empty && empty_required_value?(value)
    return false unless value.kind_of?(String) || value.kind_of?(NilClass)

    return true if interfaces.include?(value)

    super
  end
end

end
