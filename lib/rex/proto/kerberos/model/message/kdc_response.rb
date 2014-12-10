module Rex
  module Proto
    module Kerberos
      module Model
        module Message
          class KdcResponse < Element
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
          end
        end
      end
    end
  end
end