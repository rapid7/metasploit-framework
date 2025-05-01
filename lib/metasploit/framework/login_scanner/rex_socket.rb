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
          # @!attribute ssl_verify_mode
          #   @return [String] the SSL certification verification mechanism
          attr_accessor :ssl_verify_mode
          # @!attribute ssl_cipher
          #   @return [String] The SSL cipher to use for the context
          attr_accessor :ssl_cipher

          private

          def rhost
            host
          end

          def rport
            port
          end

          def chost
            local_host || '0.0.0.0'
          end

          def cport
            local_port || 0
          end
        end
      end
    end
  end
end
