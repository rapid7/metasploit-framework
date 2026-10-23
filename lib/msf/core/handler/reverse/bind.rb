# -*- coding: binary -*-

module Msf
  module Handler
    module Reverse
      # Shared bind address functionality for reverse handlers.
      module Bind
        def is_loopback_address?(address)
          a = IPAddr.new(address.to_s)
          IPAddr.new('127.0.0.1/8').include?(a) || IPAddr.new('::1').include?(a)
        rescue IPAddr::Error
          false
        end

        # A list of addresses to attempt to bind, in preferred order.
        #
        # @return [Array<String>] a two-element array. The first element will be
        #   the address that `datastore['LHOST']` resolves to, the second will
        #   be the INADDR_ANY address for IPv4 or IPv6, depending on the version
        #   of the first element.
        def bind_addresses
          if !datastore['ReverseListenerBindAddress'].to_s.empty?
            bind_addr = datastore['ReverseListenerBindAddress']
            any = Rex::Socket.is_ipv6?(bind_addr) ? '::0' : '0.0.0.0'
            return [ Rex::Socket.addr_atoi(bind_addr) == 0 ? any : bind_addr ]
          end

          begin
            addr_nbo = Rex::Socket.resolv_nbo(datastore['LHOST'])
          rescue StandardError
            print_warning("LHOST '#{datastore['LHOST']}' is not locally resolvable. Binding to 0.0.0.0. Set ReverseListenerBindAddress to override.")
            return ['0.0.0.0']
          end

          addr = Rex::Socket.addr_ntoa(addr_nbo)
          any = Rex::Socket.is_ipv4?(addr) ? '0.0.0.0' : '::0'

          if is_loopback_address?(addr)
            print_warning("You are binding to a loopback address by setting LHOST to #{addr}. Did you want ReverseListenerBindAddress?")
          end

          [addr, any]
        end
      end
    end
  end
end
