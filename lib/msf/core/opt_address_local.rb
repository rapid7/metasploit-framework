# -*- coding: binary -*-
require 'network_interface'

module Msf

###
#
# Network address option that allows referencing an address based on the name of the interface it's associated with.
#
###
class OptAddressLocal < OptAddressRoutable

  def valid?(value, check_empty: true, datastore: nil)
    return false if check_empty && empty_required_value?(value)
    return false unless value.kind_of?(String) || value.kind_of?(NilClass)

    return true if interfaces.include?(value)

    # the 0.0.0.0 / :: addresses are valid local addresses for the purpose of binding
    return true if Rex::Socket.is_ip_addr?(value) && Rex::Socket.addr_atoi(value) == 0

    # todo: this should probably have additional validation to ensure that the address is able to be bound to, this
    # would mean that the address is either locally available, or available via a Rex::Socket channel, e.g. a Meterpreter
    # session

    super
  end
end

end
