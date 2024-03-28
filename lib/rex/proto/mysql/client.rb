require 'mysql'

module Rex
  module Proto
    module MySQL

      # This is a Rex Proto wrapper around the ::Mysql client which is currently coming from the 'ruby-mysql' gem.
      # The purpose of this wrapper is to provide 'peerhost' and 'peerport' methods to ensure the client interfaces
      # are consistent between various SQL implementations/protocols.
      class Client < ::Mysql
        # @return [String] The remote IP address that the Mysql server is running on
        def peerhost
          io.remote_address.ip_address
        end

        # @return [Integer] The remote port that the Mysql server is running on
        def peerport
          io.remote_address.ip_port
        end

        # @return [String] The remote peer information containing IP and port
        def peerinfo
          "#{peerhost}:#{peerport}"
        end

        # @return [String] The database this client is currently connected to
        def current_database
          # Current database is stored as an array under the type 1 key.
          session_track.fetch(1, ['']).first
        end

        # @return [Hash] Server version variables:
        #  * :arch [String] The server architecture.
        #  * :platform [String] The server platform.
        #  * :hostname [String] The server hostname.
        #  * :datadir [String] The server data directory.
        #  * :version [String] The server version. This is the same as calling #server_info on the MySQL client.
        def query_server_vars
          result = {}

          server_vars = query('show variables').entries
          server_vars.each do |server_var|
            name, value = server_var

            case name
            when 'version_compile_machine'
              result[:arch] = value
            when 'version_compile_os'
              result[:platform] = value
            else
              result[name.to_s] = value
            end
          end

          result
        end
      end
    end
  end
end
