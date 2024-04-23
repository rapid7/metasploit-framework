# -*- coding: binary -*-

require 'rex/socket'
require 'forwardable'

module Rex
module Proto
module DNS
  ##
  # This class manages statically defined hostnames for DNS resolution where each name is a mapping to an IPv4 and or
  # an IPv6 address. A single hostname can only map to one address of each family.
  ##
  class StaticHostnames
    extend Forwardable

    def_delegators :@hostnames, :each, :each_with_index, :length, :empty?, :sort_by

    # @param [Hash<String, IPAddr>] hostnames The hostnames to IP address mappings to initialize with.
    def initialize(hostnames: nil)
      @hostnames = {}
      if hostnames
        hostnames.each do |hostname, ip_address|
          add(hostname, ip_address)
        end
      end
    end

    # Locate and parse a hosts file on the system. Only the first hostname to IP address definition is used which
    # replicates the behavior of /etc/hosts on Linux. Loaded definitions are merged with existing definitions.
    def parse_hosts_file
      path = %w[
        %WINDIR%\system32\drivers\etc\hosts
        /etc/hosts
        /data/data/com.termux/files/usr/etc/hosts
      ].find do |path|
        path = File.expand_path(path)
        File.file?(path) && File.readable?(path)
      end
      return unless path

      path = File.expand_path(path)
      ::IO.foreach(path) do |line|
        words = line.split
        next unless words.length > 1 && Rex::Socket.is_ip_addr?(words.first)

        ip_address = IPAddr.new(words.shift)
        words.each do |hostname|
          add(hostname, ip_address)
        end
      end
    end

    # Get an IP address of the specified type for the hostname. Only the first address is returned in cases where
    # multiple addresses are defined.
    #
    # @param [String] hostname The hostname to retrieve an address for.
    # @param [Integer] type The family of address to return represented as a DNS type (either A or AAAA).
    # @return Returns the IP address if it was found, otherwise nil.
    # @rtype [IPAddr, nil]
    def get1(hostname, type = Dnsruby::Types::A)
      get(hostname, type).first
    end

    # Get all IP addresses of the specified type for the hostname.
    #
    # @param [String] hostname The hostname to retrieve an address for.
    # @param [Integer] type The family of address to return represented as a DNS type (either A or AAAA).
    # @return Returns an array of IP addresses.
    # @rtype [Array<IPAddr>]
    def get(hostname, type = Dnsruby::Types::A)
      hostname = hostname.downcase
      @hostnames.fetch(hostname, {}).fetch(type, []).dup
    end

    # Add an IP address for the specified hostname.
    #
    # @param [String] hostname The hostname whose IP address is being defined.
    # @param [IPAddr, String] ip_address The IP address that is being defined for the hostname. If this value is a
    #   string, it will be converted to an IPAddr instance.
    def add(hostname, ip_address)
      unless self.class.is_valid_hostname?(hostname)
        # it is important to validate the hostname because assumptions about what characters it may contain are made
        # when saving and loading it from the configuration
        raise ::ArgumentError.new("Invalid hostname: #{hostname}")
      end

      ip_address = IPAddr.new(ip_address) if ip_address.is_a?(String) && Rex::Socket.is_ip_addr?(ip_address)

      hostname = hostname.downcase.delete_suffix('.')
      this_host = @hostnames.fetch(hostname, {})
      if ip_address.family == ::Socket::AF_INET
        type = Dnsruby::Types::A
      else
        type = Dnsruby::Types::AAAA
      end
      this_type = this_host.fetch(type, [])
      this_type << ip_address unless this_type.include?(ip_address)
      this_host[type] = this_type
      @hostnames[hostname] = this_host
      nil
    end

    # Delete an IP address for the specified hostname.
    #
    # @param [String] hostname The hostname whose IP address is being undefined.
    # @param [IPAddr, String] ip_address The IP address that is being undefined. If this value is a string, it will be
    #   converted to an IPAddr instance.
    def delete(hostname, ip_address)
      ip_address = IPAddr.new(ip_address) if ip_address.is_a?(String) && Rex::Socket.is_ip_addr?(ip_address)
      if ip_address.family == ::Socket::AF_INET
        type = Dnsruby::Types::A
      else
        type = Dnsruby::Types::AAAA
      end

      hostname = hostname.downcase
      this_host = @hostnames.fetch(hostname, {})
      this_type = this_host.fetch(type, [])
      this_type.delete(ip_address)
      if this_type.empty?
        this_host.delete(type)
      else
        this_host[type] = this_type
      end
      if this_host.empty?
        @hostnames.delete(hostname)
      else
        @hostnames[hostname] = this_host
      end

      nil
    end

    # Delete all hostname to IP address definitions.
    def flush
      @hostnames.clear
    end

    def self.is_valid_hostname?(name)
      # check if it appears to be a fully qualified domain name, e.g. www.metasploit.com
      return true if Rex::Socket.is_name?(name)

      # check if it appears to at least be a valid hostname, e.g. localhost
      return true if (name =~ /^([a-z0-9][a-z0-9\-]{0,61})?[a-z0-9]$/i) && (name =~ /\s/).nil?

      false
    end
  end
end
end
end
