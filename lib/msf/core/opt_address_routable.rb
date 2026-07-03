# -*- coding: binary -*-

module Msf

  ###
  #
  # Routable network address option.
  #
  ###
  class OptAddressRoutable < OptAddress
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
      return normalize_interface(value) if interfaces.include?(value)
      return normalize_ip_address(value) if Rex::Socket.is_ip_addr?(value)
    end

    def valid?(value, check_empty: true, datastore: nil)
      return false if check_empty && empty_required_value?(value)
      return false unless value.kind_of?(String) || value.kind_of?(NilClass)

      return true if interfaces.include?(value)

      return false if Rex::Socket.is_ip_addr?(value) && Rex::Socket.addr_atoi(value) == 0

      if Rex::Socket.is_ipv4?(value)
        ip_addr = IPAddr.new(value)
        return false if IPAddr.new('0.0.0.0/8').include? ip_addr   # this network
        return false if IPAddr.new('224.0.0.0/4').include? ip_addr # multicast
        return false if IPAddr.new('240.0.0.0/4').include? ip_addr # reserved
        return false if IPAddr.new('255.255.255.255') == ip_addr   # broadcast
      end

      super
    end

    private

    def normalize_interface(value)
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

    def normalize_ip_address(value)
      IPAddr.new(value).to_s
    end
  end
end
