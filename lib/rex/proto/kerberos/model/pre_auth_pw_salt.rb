# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a PA-PW-SALT structure,
        # which in practise appears to be a MS-specific implementation detail
        # of Kerberos, which contains information about login status
        class PreAuthPwSalt < Element

          # @!attribute nt_status
          #   @return [Integer] The NT Status from a login attempt
          attr_accessor :nt_status
          # @!attribute Reserved
          #   @return [Integer] Reserved
          attr_accessor :reserved
          # @!attribute type
          #   @return [Integer] Uncertain what this represents
          attr_accessor :flags




          # Decodes the Rex::Proto::Kerberos::Model::PreAuthPwSalt from an input
          #
          # @param input [String] the input to decode from
          # @return [self] if decoding succeeds
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode(input)
            case input
            when String
              decode_string(input)
            else
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode PA-PW-SALT, invalid input'
            end

            self
          end

          def encode
            [self.nt_status, self.reserved, self.flags].pack('VVV')
          end

          private

          # Decodes a Rex::Proto::Kerberos::Model::PreuAuthPwSalt from a String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            if input.length != 12
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode PA-PW-SALT, invalid input'
            end
            self.nt_status, self.reserved, self.flags = input.unpack('VVV')
          end
        end
      end
    end
  end
end
