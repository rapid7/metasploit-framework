# -*- coding: binary -*-

require 'rex/socket'
require 'forwardable'

module Rex
module Proto
module DNS
  class StaticHostnames
    extend Forwardable

    def_delegators :@hostnames, :each, :length, :empty?

    def initialize(hostnames: nil)
      @hostnames = {}
      if hostnames
        hostnames.each do |hostname, ip_address|
          add(hostname, ip_address)
        end
      end
    end

    def parse_hosts_file
      path = '/etc/hosts'
      return unless File.file?(path) && File.readable?(path)

      hostnames = {}
      ::IO.foreach(path) do |line|
        words = line.split
        next unless words.length > 1 && Rex::Socket.is_ip_addr?(words.first)

        ip_address = IPAddr.new(words.shift)
        words.each do |hostname|
          hostname = hostname.downcase
          this_host = hostnames.fetch(hostname, {})
          if ip_address.family == ::Socket::AF_INET
            type = Dnsruby::Types::A
          else
            type = Dnsruby::Types::AAAA
          end
          next if this_host.key?(type) # only honor the first definition

          this_host[type] = ip_address
          hostnames[hostname] = this_host
        end
      end
      @hostnames.merge!(hostnames)
    end

    def get(hostname, type = Dnsruby::Types::A)
      hostname = hostname.downcase
      @hostnames.fetch(hostname, {}).fetch(type, nil)
    end

    def add(hostname, ip_address)
      hostname = hostname.downcase
      ip_address = IPAddr.new(ip_address) if Rex::Socket.is_ip_addr?(ip_address)

      addresses = @hostnames.fetch(hostname, {})
      if ip_address.family == ::Socket::AF_INET
        addresses[Dnsruby::Types::A] = ip_address
      elsif ip_address.family == ::Socket::AF_INET6
        addresses[Dnsruby::Types::AAAA] = ip_address
      end
      @hostnames[hostname] = addresses
      nil
    end

    def delete(hostname, type = Dnsruby::Types::A)
      hostname = hostname.downcase
      addresses = @hostnames.fetch(hostname, {})
      addresses.delete(type)
      if addresses.length == 0
        @hostnames.delete(hostname)
      else
        @hostnames[hostname] = addresses
      end

      nil
    end

    def flush
      @hostnames.clear
    end
  end
end
end
end
