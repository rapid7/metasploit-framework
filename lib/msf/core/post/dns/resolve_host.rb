# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/stdapi/constants'

module Msf
  class Post
    module DNS
      ###
      #
      # This module resolves session DNS
      #
      ###
      module ResolveHost
        # Takes the host name and resolves the IP
        #
        # @param [String] host
        # @param [Integer] family AF_INET for IPV4 and AF_INET6 for IPV6
        # @return [Hash] The resolved IPs
        def resolve_host(host, family)
          if client.respond_to?(:net) && client.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_NET_RESOLVE_HOST)
            resolved_host = client.net.resolve.resolve_host(host, family)
            resolved_host.reject { |k, _v| k == :ip }
          else
            ips = []
            data = cmd_exec("nslookup #{host}")
            if data =~ /Name/
              # Remove unnecessary data and get the section with the addresses
              returned_data = data.split(/Name:/)[1..]
              # check each element of the array to see if they are IP
              returned_data.each do |entry|
                ip_list = entry.gsub(/\r\n\t |\r\n|Aliases:|Addresses:|Address:/, ' ').split(' ') - [host]
                filtered_ips = filter_ips(ip_list, family)
                ips = filtered_ips unless filtered_ips.empty?
              end
              # If nslookup responds with "no answer", fall back to resolving via host command
            elsif data =~ /No answer/
              data = cmd_exec("host #{host}")
              if data =~ /has address/
                # Remove unnecessary data and get the section with the addresses
                returned_data = data.split("\n")[...-1]
                # check each element of the array to see if they are IP
                ip_list = returned_data.map { |entry| entry.split(' ').last }
                filtered_ips = filter_ips(ip_list, family)
                ips = filtered_ips unless filtered_ips.empty?
              end
            end
            { hostname: host, ips: ips }
          end
        end

        # Takes the host and family and returns the IP address if it matches the appropriate family
        # Needed to handle request that fallback to nslookup or host, as they return both IPV4 and IPV6.
        #
        # @param [Array] ips
        # @param [Integer] family
        # @return [Array] ips
        def filter_ips(ips, family)
          filtered_ips = []
          ips.each do |ip|
            if family == AF_INET
              filtered_ips << ip if !!(ip =~ Resolv::IPv4::Regex)
            elsif family == AF_INET6
              filtered_ips << ip if !!(ip =~ Resolv::IPv6::Regex)
            end
          end

          filtered_ips
        end
      end
    end
  end
end
