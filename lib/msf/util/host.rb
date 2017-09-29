# -*- coding: binary -*-

module Msf
  module Util
    module Host

      #
      # Returns something suitable for the +:host+ parameter to the various report_* methods
      #
      # Takes a Host object, a Session object, an Msf::Session object or a String
      # address
      #
      def self.normalize_host(host)
        return host if defined?(::Mdm) && host.kind_of?(::Mdm::Host)
        norm_host = nil

        if (host.kind_of? String)

          if Rex::Socket.is_ipv4?(host)
            # If it's an IPv4 addr with a port on the end, strip the port
            if host =~ /((\d{1,3}\.){3}\d{1,3}):\d+/
              norm_host = $1
            else
              norm_host = host
            end
          elsif Rex::Socket.is_ipv6?(host)
            # If it's an IPv6 addr, drop the scope
            address, scope = host.split('%', 2)
            norm_host = address
          else
            norm_host = Rex::Socket.getaddress(host, true)
          end
        elsif defined?(::Mdm) && host.kind_of?(::Mdm::Session)
          norm_host = host.host
        elsif host.respond_to?(:session_host)
          # Then it's an Msf::Session object
          norm_host = host.session_host
        end

        # If we got here and don't have a norm_host yet, it could be a
        # Msf::Session object with an empty or nil tunnel_host and tunnel_peer;
        # see if it has a socket and use its peerhost if so.
        if (
        norm_host.nil? &&
            host.respond_to?(:sock) &&
            host.sock.respond_to?(:peerhost) &&
            host.sock.peerhost.to_s.length > 0
        )
          norm_host = session.sock.peerhost
        end
        # If We got here and still don't have a real host, there's nothing left
        # to try, just log it and return what we were given
        if !norm_host
          dlog("Host could not be normalized: #{host.inspect}")
          norm_host = host
        end

        norm_host
      end
    end
  end
end
