require 'net/ldap'

module Rex
  module Proto
    module LDAP

      # This is a Rex Proto wrapper around the Net::LDAP client which is currently coming from the 'net-ldap' gem.
      # The purpose of this wrapper is to provide 'peerhost' and 'peerport' methods to ensure the client interfaces
      # are consistent between various session clients.
      class Client < Net::LDAP
        # @return [String] The remote IP address that LDAPr is running on
        def peerhost
          host
        end

        # @return [Integer] The remote port that LDAP is running on
        def peerport
          port
        end

        # @return [String] The remote peer information containing IP and port
        def peerinfo
          "#{peerhost}:#{peerport}"
        end
      end
    end
  end
end
