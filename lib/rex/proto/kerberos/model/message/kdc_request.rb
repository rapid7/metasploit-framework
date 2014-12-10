# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Message
          class KdcRequest < Element
            # @!attribute pvno
            #   @return [Fixnum] The protocol version number
            attr_accessor :pvno
            # @!attribute msg_type
            #   @return [Fixnum] The type of a protocol message
            attr_accessor :msg_type
            # @!attribute pa_data
            #   @return [Array<Rex::Proto::Kerberos::Model::Field::PreAuthData>] Authentication information which may
            #   be needed before credentials can be issued or decrypted
            attr_accessor :pa_data
            # @!attribute req_body
            #   @return [Rex::Proto::Kerberos::Model::Field::KdcRequestBody] The request body
            attr_accessor :req_body

            def decode(input)
              case input
              when String
                decode_string(input)
              when OpenSSL::ASN1::ASN1Data
                decode_asn1(input)
              else
                raise ::RuntimeError, 'Failed to decode Principal Name, invalid input'
              end

              self
            end

            def encode
              raise ::RuntimeError, 'KdcRequest encoding not supported'
            end

            private

            def decode_string(input)
              asn1 = OpenSSL::ASN1.decode(input)

              decode_asn1(asn1)
            end

            def decode_asn1(input)
              seq_values    = input.value[0].value
              self.pvno     = decode_asn1_pvno(seq_values[0])
              self.msg_type = decode_asn1_msg_type(seq_values[1])
              self.pa_data  = decode_asn1_pa_data(seq_values[2])
              self.req_body = decode_asn1_req_body(seq_values[3])
            end

            def decode_asn1_pvno(input)
              input.value[0].value.to_i
            end

            def decode_asn1_msg_type(input)
              input.value[0].value.to_i
            end

            def decode_asn1_pa_data(input)
              pre_auth = []
              input.value[0].value.each do |pre_auth_data|
                pre_auth << Rex::Proto::Kerberos::Model::Field::PreAuthData.decode(pre_auth_data)
              end

              pre_auth
            end

            def decode_asn1_req_body(input)
              Rex::Proto::Kerberos::Model::Field::KdcRequestBody.decode(input.value[0], msg_type)
            end
          end
        end
      end
    end
  end
end