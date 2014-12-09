module Rex
  module Kerberos
    module Model
      module Message
        class KdcRequest
          # @!attribute pvno
          #   @return [Fixnum] The protocol version number
          attr_accessor :pvno
          # @!attribute msg_type
          #   @return [Fixnum] The type of a protocol message
          attr_accessor :msg_type
          # @!attribute pa_data
          #   @return [Rex::Proto::Kerberos::Model::Field::PreAuthData] Authentication information which may
          #   be needed before credentials can be issued or decrypted
          attr_accessor :pa_data
          # @!attribute req_body
          #   @return [Rex::Proto::Kerberos::Model::Field::KdcRequestBody] The request body
          attr_accessor :req_body
        end
      end
    end
  end
end