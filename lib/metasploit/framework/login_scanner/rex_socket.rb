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

          # @!attribute max_send_size
          #   @return [Fixnum] The max size of the data to encapsulate in a single packet
          attr_accessor :max_send_size
          # @!attribute send_delay
          #   @return [Fixnum] The delay between sending packets
          attr_accessor :send_delay
          # @!attribute ssl
          #   @return [Boolean] Whether the socket should use ssl
          attr_accessor :ssl
          # @!attribute ssl_version
          #   @return [String] The version of SSL to implement
          attr_accessor :ssl_version

          validates :max_send_size,
                    presence: true,
                    numericality: {
                        only_integer:             true,
                        greater_than_or_equal_to: 0
                    }

          validates :send_delay,
                    presence: true,
                    numericality: {
                        only_integer:             true,
                        greater_than_or_equal_to: 0
                    }


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
