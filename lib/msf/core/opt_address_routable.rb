# -*- coding: binary -*-

module Msf

  ###
  #
  # Routable network address option.
  #
  ###
  class OptAddressRoutable < OptAddress

    def valid?(value, check_empty: true)
      return false if Rex::Socket.is_ip_addr?(value) && Rex::Socket.addr_atoi(value) == 0
      super
    end
  end
end
