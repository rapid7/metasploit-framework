# -*- coding: binary -*-
require 'network_interface'

module Msf

###
#
# Network address or hostname option.
#
# Accepts an IPv4/IPv6 address, a local network interface name, or a
# syntactically valid hostname. Unlike OptAddress, DNS resolution is NOT
# performed during validation, so tunnel service hostnames (ngrok, pinggy,
# etc.) that are not resolvable from the local machine are accepted.
#
# Use this for options like LHOST where the value identifies the callback
# endpoint embedded in a payload, and may be a tunnel hostname rather than
# a locally-resolvable address.
#
###
class OptAddressOrHostname < OptAddressRoutable

  # @param resolve_names [Boolean] when true, hostname values are also resolved
  #   via DNS during validation. Use this when the value will be connected to or
  #   bound to locally, so resolution failures surface early.
  def initialize(in_name, attrs = [], resolve_names: false, **kwargs)
    super(in_name, attrs, **kwargs)
    @resolve_names = resolve_names
  end

  def type
    'address'
  end

  def valid?(value, check_empty: true, datastore: nil)
    return false if check_empty && empty_required_value?(value)
    return false unless value.kind_of?(String) || value.kind_of?(NilClass)

    if value && !value.empty?
      return true if interfaces.include?(value)

      # Reject anything that looks like a dotted-decimal number sequence
      # (e.g. "192.0.2", "192.0.2.0.0") - Rex::Socket.is_name? accepts numeric
      # DNS labels, so these would pass without this guard. Require it to be a
      # valid IPv4 address, then delegate to parent for routable checks.
      if value =~ /^\d+(\.\d+)+$/
        return false unless Rex::Socket.is_ipv4?(value)
        return super
      end

      return super if Rex::Socket.is_ip_addr?(value)

      if Rex::Socket.is_name?(value)
        return true unless @resolve_names
        begin
          ::Rex::Socket.getaddress(value, true)
          return true
        rescue
          return false
        end
      end

      return false
    end

    true
  end

  def normalize(value)
    return unless value.kind_of?(String)
    return normalize_interface(value) if interfaces.include?(value)
    return normalize_ip_address(value) if Rex::Socket.is_ip_addr?(value)
    value
  end

end

end
