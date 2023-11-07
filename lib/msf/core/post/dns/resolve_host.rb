# -*- coding: binary -*-

module Msf
  class Post
    module DNS
      ###
      #
      # This module resolves session DNS
      #
      ###
      module ResolveHost
        # Takes the host name and makes use of nslookup to resolve the IP
        #
        # @param [String] host Hostname
        # @return [Array, nil] result[:ips], ips The resolved IPs
        def resolve_host(host, family)
          if client.respond_to?(:net) && client.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_NET_RESOLVE_HOST)
            result = client.net.resolve.resolve_host(host, family)
            result[:ips]
          else
            ips = []
            data = cmd_exec("nslookup #{host}")
            if data =~ /Name/
              # Remove unnecessary data and get the section with the addresses
              returned_data = data.split(/Name:/)[1]
              # check each element of the array to see if they are IP
              returned_data.gsub(/\r\n\t |\r\n|Aliases:|Addresses:|Address:/, ' ').split(' ').each do |e|
                if Rex::Socket.dotted_ip?(e)
                  ips << e
                end
              end
            end
            ips
          end
        end
      end
    end
  end
end
