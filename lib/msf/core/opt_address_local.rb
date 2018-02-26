# -*- coding: binary -*-
require 'network_interface'

module Msf

###
#
# Network address option.
#
###
class OptAddressLocal < OptAddress
  def normalize(value)
    return nil unless value.kind_of?(String)
    
    if NetworkInterface.interfaces.include?(value)
      ip_address = NetworkInterface.addresses(value).values.flatten.collect{|x| x['addr']}.select do |addr|
        begin
          IPAddr.new(addr).ipv4?
        rescue IPAddr::InvalidAddressError => e
          false
        end
      end

      return false if ip_address.blank?
      return ip_address.first
    end
    
    return value
  end
  
  def valid?(value, check_empty: true)
    return false if check_empty && empty_required_value?(value)
    return false unless value.kind_of?(String) or value.kind_of?(NilClass)
   
    return true if NetworkInterface.interfaces.include?(value)

    return super
  end
end

end
