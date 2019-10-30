# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a Kerberos KDC-REQ-BODY (request body) data
        # definition
        class KdcRequestBody < Element
          # @!attribute options
          #   @return [Integer] The ticket flags
          attr_accessor :options
          # @!attribute cname
          #   @return [Rex::Proto::Kerberos::Model::PrincipalName] The name part of the client's principal identifier
          attr_accessor :cname
          # @!attribute realm
          #   @return [String] The realm part of the server's principal identifier
          attr_accessor :realm
          # @!attribute sname
          #   @return [Rex::Proto::Kerberos::Model::PrincipalName] The name part of the server's identity
          attr_accessor :sname
          # @!attribute from
          #   @return [Time] Start time when the ticket is to be postdated
          attr_accessor :from
          # @!attribute till
          #   @return [Time] Expiration date requested by the client
          attr_accessor :till
          # @!attribute rtime
          #   @return [Time] Optional requested renew-till time
          attr_accessor :rtime
          # @!attribute nonce
          #   @return [Integer] random number
          attr_accessor :nonce
          # @!attribute etype
          #   @return [Array<Integer>] The desired encryption algorithm to be used in the response
          attr_accessor :etype
          # @!attribute enc_auth_data
          #   @return [Rex::Proto::Kerberos::Model::EncryptedData] An encoding of the desired authorization-data encrypted
          attr_accessor :enc_auth_data

          # Decodes the Rex::Proto::Kerberos::Model::KdcRequestBody attributes from input
          #
          # @param input [String, OpenSSL::ASN1::Sequence] the input to decode from
          # @return [self] if decoding succeeds
          # @raise [RuntimeError] if decoding doesn't succeed
          def decode(input)
            case input
            when String
              decode_string(input)
            when OpenSSL::ASN1::Sequence
              decode_asn1(input)
            else
              raise ::RuntimeError, 'Failed to decode KdcRequestBody, invalid input'
            end

            self
          end

          # Encodes the Rex::Proto::Kerberos::Model::KdcRequestBody into an ASN.1 String
          #
          # @return [String]
          def encode
            elems = []

            elems << OpenSSL::ASN1::ASN1Data.new([encode_options], 0, :CONTEXT_SPECIFIC) if options
            elems << OpenSSL::ASN1::ASN1Data.new([encode_cname], 1, :CONTEXT_SPECIFIC) if cname
            elems << OpenSSL::ASN1::ASN1Data.new([encode_realm], 2, :CONTEXT_SPECIFIC) if realm
            elems << OpenSSL::ASN1::ASN1Data.new([encode_sname], 3, :CONTEXT_SPECIFIC) if sname
            elems << OpenSSL::ASN1::ASN1Data.new([encode_from], 4, :CONTEXT_SPECIFIC) if from
            elems << OpenSSL::ASN1::ASN1Data.new([encode_till], 5, :CONTEXT_SPECIFIC) if till
            elems << OpenSSL::ASN1::ASN1Data.new([encode_rtime], 6, :CONTEXT_SPECIFIC) if rtime
            elems << OpenSSL::ASN1::ASN1Data.new([encode_nonce], 7, :CONTEXT_SPECIFIC) if nonce
            elems << OpenSSL::ASN1::ASN1Data.new([encode_etype], 8, :CONTEXT_SPECIFIC) if etype
            elems << OpenSSL::ASN1::ASN1Data.new([encode_enc_auth_data], 10, :CONTEXT_SPECIFIC) if enc_auth_data

            seq = OpenSSL::ASN1::Sequence.new(elems)

            seq.to_der
          end

          # Makes a checksum from the Rex::Proto::Kerberos::Model::KdcRequestBody
          #
          # @param etype [Integer] the crypto schema to checksum
          # @return [String] the checksum
          # @raise [NotImplementedError] if the encryption schema isn't supported
          def checksum(etype)
            data = self.encode

            res = ''
            case etype
            when RSA_MD5
              res = checksum_rsa_md5(data)
            else
              raise ::NotImplementedError, 'EncryptedData schema is not supported'
            end

            res
          end

          private

          # Encodes the options
          #
          # @return [OpenSSL::ASN1::BitString]
          def encode_options
            OpenSSL::ASN1::BitString.new([options].pack('N'))
          end

          # Encodes the cname
          #
          # @return [String]
          def encode_cname
            cname.encode
          end

          # Encodes the realm
          #
          # @return [OpenSSL::ASN1::GeneralString]
          def encode_realm
            OpenSSL::ASN1::GeneralString.new(realm)
          end

          # Encodes the sname
          #
          # @return [String]
          def encode_sname
            sname.encode
          end

          # Encodes the from
          #
          # @return [OpenSSL::ASN1::GeneralizedTime]
          def encode_from
            OpenSSL::ASN1::GeneralizedTime.new(from)
          end

          # Encodes the till
          #
          # @return [OpenSSL::ASN1::GeneralizedTime]
          def encode_till
            OpenSSL::ASN1::GeneralizedTime.new(till)
          end

          # Encodes the rtime
          #
          # @return [OpenSSL::ASN1::GeneralizedTime]
          def encode_rtime
            OpenSSL::ASN1::GeneralizedTime.new(rtime)
          end

          # Encodes the nonce
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_nonce
            bn = OpenSSL::BN.new(nonce.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the etype
          #
          # @return [OpenSSL::ASN1::Sequence]
          def encode_etype
            encoded_types = []
            etype.each do |member|
              bn = OpenSSL::BN.new(member.to_s)
              int = OpenSSL::ASN1::Integer.new(bn)
              encoded_types << int
            end

            OpenSSL::ASN1::Sequence.new(encoded_types)
          end

          # Encodes the enc_auth_data
          #
          # @return [String]
          def encode_enc_auth_data
            enc_auth_data.encode
          end

          # Decodes a Rex::Proto::Kerberos::Model::KdcRequestBody from an String
          #
          # @param input [String] the input to decode from
          # @raise [RuntimeError] if decoding doesn't succeed
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::KdcRequestBody from an
          # OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          # @raise [RuntimeError] if decoding doesn't succeed
          def decode_asn1(input)
            seq_values = input.value

            seq_values.each do |val|
              case val.tag
              when 0
                self.options = decode_options(val)
              when 1
                self.cname = decode_cname(val)
              when 2
                self.realm = decode_realm(val)
              when 3
                self.sname = decode_sname(val)
              when 4
                self.from = decode_from(val)
              when 5
                self.till = decode_till(val)
              when 6
                self.rtime = decode_rtime(val)
              when 7
                self.nonce = decode_nonce(val)
              when 8
                self.etype = decode_etype(val)
              when 10
                self.enc_auth_data = decode_enc_auth_data(val)
              else
                raise ::RuntimeError, 'Failed to decode KdcRequestBody SEQUENCE'
              end
            end
          end

          # Decodes the options field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_options(input)
            input.value[0].value.unpack('N')[0]
          end

          # Decodes the cname field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Model::PrincipalName]
          def decode_cname(input)
            Rex::Proto::Kerberos::Model::PrincipalName.decode(input.value[0])
          end

          # Decodes the realm field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [String]
          def decode_realm(input)
            input.value[0].value
          end

          # Decodes the sname field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Model::PrincipalName]
          def decode_sname(input)
            Rex::Proto::Kerberos::Model::PrincipalName.decode(input.value[0])
          end

          # Decodes the from field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Time]
          def decode_from(input)
            input.value[0].value
          end

          # Decodes the till field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Time]
          def decode_till(input)
            input.value[0].value
          end

          # Decodes the rtime field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Time]
          def decode_rtime(input)
            input.value[0].value
          end

          # Decodes the nonce field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_nonce(input)
            input.value[0].value.to_i
          end

          # Decodes the etype field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Array<Integer>]
          def decode_etype(input)
            encs = []
            input.value[0].value.each do |enc|
              encs << enc.value.to_i
            end
            encs
          end

          # Decodes the enc_auth_data field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Model::EncryptedData]
          def decode_enc_auth_data(input)
            Rex::Proto::Kerberos::Model::EncryptedData.decode(input.value[0])
          end
        end
      end
    end
  end
end
