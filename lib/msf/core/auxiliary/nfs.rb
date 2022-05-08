# -*- coding: binary -*-

module Msf
  ###
  #
  # This module provides methods for working with NFS
  #
  ###
  module Auxiliary::Nfs
    include Auxiliary::Scanner

    def initialize(info = {})
      super
      register_options(
        [
          OptAddressLocal.new('LHOST', [false, 'IP to match shares against', Rex::Socket.source_address]),
          OptString.new('HOSTNAME', [false, 'Hostname to match shares against', ''])
        ]
      )
    end

    def can_mount?(locations)
      # attempts to validate if we'll be able to open it or not based on:
      # 1. its a wildcard, thus we can open it
      # 2. hostname isn't blank and its in the list
      # 3. our IP is explicitly listed
      # 4. theres a CIDR notation that we're included in.
      return true unless datastore['Mountable']
      return true if locations.include? '*'
      return true if !datastore['HOSTNAME'].blank? && locations.include?(datastore['HOSTNAME'])
      return true if !datastore['LHOST'].empty? && locations.include?(datastore['LHOST'])

      locations.each do |location|
        # if it has a subnet mask, convert it to cidr
        if %r{(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})} =~ location
          location = "#{Regexp.last_match(1)}#{Rex::Socket.addr_atoc(Regexp.last_match(2))}"
        end
        return true if Rex::Socket::RangeWalker.new(location).include?(datastore['LHOST'])
        # at this point we assume its a hostname, so we use Ruby's File fnmatch so that it proceses the wildcards
        # as its a quick and easy way to use glob matching for wildcards and get a boolean response
        return true if File.fnmatch(location, datastore['HOSTNAME'])
      end
      false
    end
  end
end
