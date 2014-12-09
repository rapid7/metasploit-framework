module Rex
  module Proto
    module Kerberos
      module Model
        module Field
          class KdcRequestBody < Element
            # @!attribute options
            #   @return [Fixnum] The ticket flags
            attr_accessor :options
            # @!attribute cname
            #   @return [Rex::Proto::Kerberos::Type::PrincipalName] The name part of the client's principal identifier
            attr_accessor :cname
            # @!attribute realm
            #   @return [String] The realm part of the server's principal identifier
            attr_accessor :realm
            # @!attribute sname
            #   @return [Rex::Proto::Kerberos::Type::PrincipalName] The name part of the server's identity
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
            #   @return [Fixnum] random number
            attr_accessor :nonce
            # @!attribute etype
            #   @return [Array<Fixnum>] The desired encryption algorithm to be used in the response
            attr_accessor :etype
            # @!attribute enc_auth_data
            #   @return [Rex::Proto::Kerberos::Type::EncryptedData] An encoding of the desired authorization-data encrypted
            attr_accessor :enc_auth_data

            def decode(input, type_req)

              case input
              when String
                decode_string(input, type_req)
              when OpenSSL::ASN1::Sequence
                decode_asn1(input, type_req)
              else
                raise ::RuntimeError, 'Failed to decode Principal Name, invalid input'
              end

              self
            end

            def encode
              raise ::RuntimeError, 'KdcRequestBody encoding is not supported'
            end

            private

            def decode_string(input, type_req)
              asn1 = OpenSSL::ASN1.decode(input)

              decode_asn1(asn1, type_req)
            end

            def decode_asn1(input, type_req)
              case type_req
              when AS_REQ
                decode_asn1_as_req(input)
              when TGS_REQ
                decode_asn1_tgs_req(input)
              else
                raise ::RuntimeError, 'Failed to decode KDC_REQ_BODY, unknown request type'
              end
            end

            def decode_asn1_as_req(input)
              self.options = decode_options(input.value[0])
              self.cname = decode_cname(input.value[1])
              self.realm = decode_realm(input.value[2])
              self.sname = decode_sname(input.value[3])
              self.from = decode_from(input.value[4])
              self.till = decode_till(input.value[5])
              self.rtime = decode_rtime(input.value[6])
              self.nonce = decode_nonce(input.value[7])
              self.etype = decode_etype(input.value[8])
            end

            def decode_asn1_tgs_req(input)
              self.options = decode_options(input.value[0])
              self.realm = decode_realm(input.value[1])
              self.sname = decode_sname(input.value[2])
              self.from = decode_from(input.value[3])
              self.till = decode_till(input.value[4])
              self.rtime = decode_rtime(input.value[5])
              self.nonce = decode_nonce(input.value[6])
              self.etype = decode_etype(input.value[7])
              self.enc_auth_data = decode_enc_auth_data(input.value[8])
            end

            def decode_options(input)
              input.value[0].value.unpack('N')[0]
            end

            def decode_cname(input)
              Rex::Proto::Kerberos::Model::Type::PrincipalName.decode(input.value[0])
            end

            def decode_realm(input)
              input.value[0].value
            end

            def decode_sname(input)
              Rex::Proto::Kerberos::Model::Type::PrincipalName.decode(input.value[0])
            end

            def decode_from(input)
              input.value[0].value
            end

            def decode_till(input)
              input.value[0].value
            end

            def decode_rtime(input)
              input.value[0].value
            end

            def decode_nonce(input)
              input.value[0].value.to_i
            end

            def decode_etype(input)
              encs = []
              input.value[0].value.each do |enc|
                encs << enc.value.to_i
              end
              encs
            end

            def decode_enc_auth_data(input)
              Rex::Proto::Kerberos::Model::Type::EncryptedData.decode(input.value[0])
            end
          end
        end
      end
    end
  end
end