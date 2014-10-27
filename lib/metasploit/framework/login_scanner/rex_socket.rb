require 'metasploit/framework/login_scanner'

module Metasploit
  module Framework
    module LoginScanner

      # This module provides the common mixin behaviour for
      # LoginScanner objects that rely on Rex Sockets for their
      # underlying communication.
      module RexSocket
        extend ActiveSupport::Concern

        included do

          # @!attribute ssl
          #   @return [Boolean] Whether the socket should use ssl
          attr_accessor :ssl
          # @!attribute ssl_version
          #   @return [String] The version of SSL to implement
          attr_accessor :ssl_version

          private

          def chost
            '0.0.0.0'
          end

          def cport
            0
          end

          def rhost
            host
          end

          def rport
            port
          end
        end
      end
    end
  end
end
