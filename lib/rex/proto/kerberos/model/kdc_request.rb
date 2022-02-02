# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a Kerberos KDC-REQ (request) data
        # definition
        class KdcRequest < Element
          # @!attribute pvno
          #   @return [Integer] The protocol version number
          attr_accessor :pvno
          # @!attribute msg_type
          #   @return [Integer] The type of a protocol message
          attr_accessor :msg_type
          # @!attribute pa_data
          #   @return [Array<Rex::Proto::Kerberos::Model::PreAuthData>] Authentication information which may
          #   be needed before credentials can be issued or decrypted
          attr_accessor :pa_data
          # @!attribute req_body
          #   @return [Rex::Proto::Kerberos::Model:::KdcRequestBody] The request body
          attr_accessor :req_body

          # Decodes the Rex::Proto::Kerberos::Model::KdcRequest from an input
          #
          # @param input [String, OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [self] if decoding succeeds
          # @raise [RuntimeError] if decoding doesn't succeed
          def decode(input)
            case input
            when String
              decode_string(input)
            when OpenSSL::ASN1::ASN1Data
              decode_asn1(input)
            else
              raise ::RuntimeError, 'Failed to decode KdcRequest, invalid input'
            end

            self
          end

          # Encodes the Rex::Proto::Kerberos::Model::KdcRequest into an ASN.1 String
          #
          # @return [String]
          def encode
            pvno_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_pvno], 1, :CONTEXT_SPECIFIC)
            msg_type_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_msg_type], 2, :CONTEXT_SPECIFIC)
            pa_data_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_pa_data], 3, :CONTEXT_SPECIFIC)
            req_body_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_req_body], 4, :CONTEXT_SPECIFIC)
            seq = OpenSSL::ASN1::Sequence.new([pvno_asn1, msg_type_asn1, pa_data_asn1, req_body_asn1])
            seq_asn1 = OpenSSL::ASN1::ASN1Data.new([seq], msg_type, :APPLICATION)
            seq_asn1.to_der
          end

          private

          # Encodes the pvno field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_pvno
            bn = OpenSSL::BN.new(pvno.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the msg_type field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_msg_type
            bn = OpenSSL::BN.new(msg_type.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the pa_data field
          #
          # @return [String]
          def encode_pa_data
            elems = []
            pa_data.each do |data|
              elems << data.encode
            end

            OpenSSL::ASN1::Sequence.new(elems)
          end

          # Encodes the req_body field
          #
          # @return [String]
          def encode_req_body
            req_body.encode
          end

          # Decodes a Rex::Proto::Kerberos::Model::KdcRequest from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::KdcRequest
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @raise [RuntimeError] if decoding doesn't succeed
          def decode_asn1(input)
            input.value[0].value.each do |val|
              case val.tag
              when 1
                self.pvno = decode_asn1_pvno(val)
              when 2
                self.msg_type = decode_asn1_msg_type(val)
              when 3
                self.pa_data  = decode_asn1_pa_data(val)
              when 4
                self.req_body = decode_asn1_req_body(val)
              else
                raise ::RuntimeError, 'Failed to decode KdcRequest SEQUENCE'
              end
            end
          end

          # Decodes the pvno from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_asn1_pvno(input)
            input.value[0].value.to_i
          end

          # Decodes the msg_type from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_asn1_msg_type(input)
            input.value[0].value.to_i
          end

          # Decodes the pa_data from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Array<Rex::Proto::Kerberos::Model::PreAuthData>]
          def decode_asn1_pa_data(input)
            pre_auth = []
            input.value[0].value.each do |pre_auth_data|
              pre_auth << Rex::Proto::Kerberos::Model::PreAuthData.decode(pre_auth_data)
            end

            pre_auth
          end

          # Decodes the req_body from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Model::KdcRequestBody]
          def decode_asn1_req_body(input)
            Rex::Proto::Kerberos::Model::KdcRequestBody.decode(input.value[0])
          end
        end
      end
    end
  end
end
