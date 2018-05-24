# -*- coding: binary -*-
require 'network_interface'

module Msf

###
#
# Network address option.
#
###
class OptAddressLocal < OptAddress
  def interfaces
    NetworkInterface.interfaces || []
  end

  def normalize(value)
    return unless value.kind_of?(String)
    return value unless interfaces.include?(value)

    ip_address = NetworkInterface.addresses(value).values.flatten.map{|x| x['addr']}.select do |addr|
      begin
        IPAddr.new(addr).ipv4?
      rescue IPAddr::InvalidAddressError
        false
      end
    end

    return if ip_address.blank?

    ip_address.first
  end

  def valid?(value, check_empty: true)
    return false if check_empty && empty_required_value?(value)
    return false unless value.kind_of?(String) || value.kind_of?(NilClass)

    return true if interfaces.include?(value)

    super
  end
end

end
