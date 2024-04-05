require 'net/ldap'

module Rex
  module Proto
    module LDAP
      # This is a Rex Proto wrapper around the Net::LDAP client which is currently coming from the 'net-ldap' gem.
      # The purpose of this wrapper is to provide 'peerhost' and 'peerport' methods to ensure the client interfaces
      # are consistent between various session clients.
      class Client < Net::LDAP

        attr_reader :socket

        # @return [String] The remote IP address that LDAP is running on
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

        # https://github.com/ruby-ldap/ruby-net-ldap/issues/11
        # We want to keep the ldap connection open to use later
        # but there's no built in way within the `Net::LDAP` library to do that
        # so we're
        # @param connect_opts [Hash] Options for the LDAP connection.
        def self._open(connect_opts)
          client = new(connect_opts)
          client._open
        end

        # https://github.com/ruby-ldap/ruby-net-ldap/issues/11
        def _open
          raise Net::LDAP::AlreadyOpenedError, 'Open already in progress' if @open_connection

          instrument 'open.net_ldap' do |payload|
            @open_connection = new_connection
            @socket = @open_connection.socket
            payload[:connection] = @open_connection
            payload[:bind] = @result = @open_connection.bind(@auth)
            return self
          end
        end

      end
    end
  end
end
