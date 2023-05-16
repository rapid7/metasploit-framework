# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # Based on https://datatracker.ietf.org/doc/html/rfc6806.html#section-11
        #    EncKDCRepPart   ::= SEQUENCE {
        #            key             [0] EncryptionKey,
        #            last-req        [1] LastReq,
        #            nonce           [2] UInt32,
        #            key-expiration  [3] KerberosTime OPTIONAL,
        #            flags           [4] TicketFlags,
        #            authtime        [5] KerberosTime,
        #            starttime       [6] KerberosTime OPTIONAL,
        #            endtime         [7] KerberosTime,
        #            renew-till      [8] KerberosTime OPTIONAL,
        #            srealm          [9] Realm,
        #            sname           [10] PrincipalName,
        #            caddr           [11] HostAddresses OPTIONAL
        #            encrypted-pa-data [12] SEQUENCE OF PA-DATA OPTIONAL
        #    }
        class EncKdcResponse < Element
          # @!attribute key
          #   @return [Rex::Proto::Kerberos::Model::EncryptionKey] The session key
          attr_accessor :key
          # @!attribute last_req
          #   @return [Array<Rex::Proto::Kerberos::Model::LastRequest>] This field is returned by the KDC and specifies the time(s)
          #   of the last request by a principal
          attr_accessor :last_req
          # @!attribute nonce
          #   @return [Integer] random number
          attr_accessor :nonce
          # @!attribute key_expiration
          #   @return [Time] The key-expiration field is part of the response from the
          #   KDC and specifies the time that the client's secret key is due to expire
          attr_accessor :key_expiration
          # @!attribute flags
          #   @return [Rex::Proto::Kerberos::Model::KdcOptionFlags] This field indicates which of various options were used or
          #   requested when the ticket was issued
          attr_accessor :flags
          # @!attribute auth_time
          #   @return [Time] the time of initial authentication for the named principal
          attr_accessor :auth_time
          # @!attribute start_time
          #   @return [Time] Specifies the time after which the ticket is valid
          attr_accessor :start_time
          # @!attribute end_time
          #   @return [Time] This field contains the time after which the ticket will
          #   not be honored (its expiration time)
          attr_accessor :end_time
          # @!attribute renew_till
          #   @return [Time] This field is only present in tickets that have the
          #   RENEWABLE flag set in the flags field.  It indicates the maximum
          #   endtime that may be included in a renewal
          attr_accessor :renew_till
          # @!attribute srealm
          #   @return [String] The realm part of the server's principal identifier
          attr_accessor :srealm
          # @!attribute sname
          #   @return [Rex::Proto::Kerberos::Model::PrincipalName] The name part of the server's identity
          attr_accessor :sname
          # @!attribute caddr
          #   @return [Rex::Proto::Kerberos::Model::HostAddress] These are the addresses from which the ticket can be used
          attr_accessor :caddr
          # @!attribute pa_data
          #   @return [Array<Rex::Proto::Kerberos::Model::PreAuthDataEntry>,nil] An array of PreAuthDataEntry. nil if not present.
          attr_accessor :pa_data

          # Decodes the Rex::Proto::Kerberos::Model::EncKdcResponse from an input
          #
          # @param input [String, OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [self] if decoding succeeds
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode(input)
            case input
            when String
              decode_string(input)
            when OpenSSL::ASN1::ASN1Data
              decode_asn1(input)
            else
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode EncKdcResponse, invalid input'
            end

            self
          end

          # Rex::Proto::Kerberos::Model::EncKdcResponse encoding isn't supported
          #
          # @raise [NotImplementedError]
          def encode
            raise ::NotImplementedError, 'EncKdcResponse encoding not supported'
          end

          private

          # Decodes a Rex::Proto::Kerberos::Model::EncKdcResponse from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::EncKdcResponse
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            input.value[0].value.each do |val|
              case val.tag
              when 0
                self.key = decode_key(val)
              when 1
                self.last_req = decode_last_req(val)
              when 2
                self.nonce = decode_nonce(val)
              when 3
                self.key_expiration = decode_key_expiration(val)
              when 4
                self.flags = decode_flags(val)
              when 5
                self.auth_time = decode_auth_time(val)
              when 6
                self.start_time = decode_start_time(val)
              when 7
                self.end_time = decode_end_time(val)
              when 8
                self.renew_till = decode_renew_till(val)
              when 9
                self.srealm = decode_srealm(val)
              when 10
                self.sname = decode_sname(val)
              when 11
                self.caddr = decode_caddr(val)
              when 12
                self.pa_data = decode_pa_data(val)
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, "Failed to decode tag #{val.tag.inspect} in ENC-KDC-RESPONSE SEQUENCE"
              end
            end
          end

          # Decodes the key from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [EncryptionKey]
          def decode_key(input)
            Rex::Proto::Kerberos::Model::EncryptionKey.decode(input.value[0])
          end

          # Decodes the last_req from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Array<Rex::Proto::Kerberos::Model::LastRequest>]
          def decode_last_req(input)
            last_requests = []
            input.value[0].value.each do |last_request|
              last_requests << Rex::Proto::Kerberos::Model::LastRequest.decode(last_request)
            end

            last_requests
          end

          # Decodes the nonce field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_nonce(input)
            input.value[0].value.to_i
          end

          # Decodes the key_expiration field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Time]
          def decode_key_expiration(input)
            input.value[0].value
          end

          # Decodes the flags field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Model::KdcOptionFlags]
          def decode_flags(input)
            flags = input.value[0].value.unpack1('N')
            # == OpenSSL::ASN1::BitString
            #
            # === Additional attributes
            # _unused_bits_: if the underlying BIT STRING's
            # length is a multiple of 8 then _unused_bits_ is 0. Otherwise
            # _unused_bits_ indicates the number of bits that are to be ignored in
            # the final octet of the BitString's _value_.
            unused_bits = input.value[0].unused_bits
            flags >>= unused_bits
            Rex::Proto::Kerberos::Model::KdcOptionFlags.new(flags)
          end

          # Decodes the auth_time field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Time]
          def decode_auth_time(input)
            input.value[0].value
          end

          # Decodes the start_time field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Time]
          def decode_start_time(input)
            input.value[0].value
          end

          # Decodes the end_time field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Time]
          def decode_end_time(input)
            input.value[0].value
          end

          # Decodes the renew_till field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Time]
          def decode_renew_till(input)
            input.value[0].value
          end

          # Decodes the srealm field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [String]
          def decode_srealm(input)
            input.value[0].value
          end

          # Decodes the sname field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Type::PrincipalName]
          def decode_sname(input)
            Rex::Proto::Kerberos::Model::PrincipalName.decode(input.value[0])
          end

          # Decodes the caddr field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Array<Rex::Proto::Model::HostAddress>]
          def decode_caddr(input)
            caddr = []
            input.value[0].value.each do |host_address_data|
              caddr << Rex::Proto::Kerberos::Model::HostAddress.decode(host_address_data)
            end
            caddr
          end

          # Decodes the pa_data field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Array<Rex::Proto::Kerberos::Model::PreAuthDataEntry>]
          def decode_pa_data(input)
            pre_auth = []
            input.value[0].value.each do |pre_auth_data|
              pre_auth << Rex::Proto::Kerberos::Model::PreAuthDataEntry.decode(pre_auth_data)
            end

            pre_auth
          end
        end
      end
    end
  end
end
