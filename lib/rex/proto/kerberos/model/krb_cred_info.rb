# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a KrbCredInfo object
        class KrbCredInfo < Element
          # @!attribute key
          #   @return [Rex::Proto::Kerberos::Model::EncryptionKey] The session key associated with a corresponding ticket in the enclosing KrbCred object
          attr_accessor :key
          # @!attribute prealm
          #   @return [String] The realm for the principal identity
          attr_accessor :prealm
          # @!attribute pname
          #   @return [Rex::Proto::Kerberos::Model::PrincipalName] The name of the principal identity
          attr_accessor :pname
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

          def ==(other)
            key == other.key &&
              prealm == other.prealm &&
              pname == other.pname &&
              flags == other.flags &&
              auth_time == other.auth_time &&
              start_time == other.start_time &&
              end_time == other.end_time &&
              renew_till == other.renew_till &&
              srealm == other.srealm &&
              sname == other.sname &&
              caddr == other.caddr
          end

          # Decodes the Rex::Proto::Kerberos::Model::KrbCredInfo from an input
          #
          # @param input [String, OpenSSL::ASN1::Sequence] the input to decode from
          # @return [self] if decoding succeeds
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode(input)
            case input
            when String
              decode_string(input)
            when OpenSSL::ASN1::Sequence
              decode_asn1(input)
            else
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode KrbCredInfo, invalid input'
            end

            self
          end

          def encode
            elems = []
            elems << OpenSSL::ASN1::ASN1Data.new([encode_key], 0, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_prealm], 1, :CONTEXT_SPECIFIC) if prealm
            elems << OpenSSL::ASN1::ASN1Data.new([encode_pname], 2, :CONTEXT_SPECIFIC) if pname
            elems << OpenSSL::ASN1::ASN1Data.new([encode_flags], 3, :CONTEXT_SPECIFIC) if flags
            elems << OpenSSL::ASN1::ASN1Data.new([encode_auth_time], 4, :CONTEXT_SPECIFIC) if auth_time
            elems << OpenSSL::ASN1::ASN1Data.new([encode_start_time], 5, :CONTEXT_SPECIFIC) if start_time
            elems << OpenSSL::ASN1::ASN1Data.new([encode_end_time], 6, :CONTEXT_SPECIFIC) if end_time
            elems << OpenSSL::ASN1::ASN1Data.new([encode_renew_till], 7, :CONTEXT_SPECIFIC) if renew_till
            elems << OpenSSL::ASN1::ASN1Data.new([encode_srealm], 8, :CONTEXT_SPECIFIC) if srealm
            elems << OpenSSL::ASN1::ASN1Data.new([encode_sname], 9, :CONTEXT_SPECIFIC) if sname
            elems << OpenSSL::ASN1::ASN1Data.new([encode_caddr], 10, :CONTEXT_SPECIFIC) if caddr
            seq = OpenSSL::ASN1::Sequence.new(elems)
            seq.to_der
          end

          private

          # Encodes the key field
          #
          # @return [String]
          def encode_key
            key.encode
          end

          # Encodes the prealm field
          #
          # @return [OpenSSL::ASN1::GeneralString]
          def encode_prealm
            OpenSSL::ASN1::GeneralString.new(prealm)
          end

          # Encodes the pname field
          #
          # @return [String]
          def encode_pname
            pname.encode
          end

          # Encodes the flags
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_flags
            OpenSSL::ASN1::BitString.new([flags.value].pack('N'))
          end

          # Encodes the auth_time
          #
          # @return [OpenSSL::ASN1::GeneralizedTime]
          def encode_auth_time
            OpenSSL::ASN1::GeneralizedTime.new(auth_time)
          end

          # Encodes the start_time
          #
          # @return [OpenSSL::ASN1::GeneralizedTime]
          def encode_start_time
            OpenSSL::ASN1::GeneralizedTime.new(start_time)
          end

          # Encodes the end_time
          #
          # @return [OpenSSL::ASN1::GeneralizedTime]
          def encode_end_time
            OpenSSL::ASN1::GeneralizedTime.new(end_time)
          end

          # Encodes the renew_till
          #
          # @return [OpenSSL::ASN1::GeneralizedTime]
          def encode_renew_till
            OpenSSL::ASN1::GeneralizedTime.new(renew_till.nil? ? 0 : renew_till)
          end

          # Encodes the srealm field
          #
          # @return [OpenSSL::ASN1::GeneralString]
          def encode_srealm
            OpenSSL::ASN1::GeneralString.new(srealm)
          end

          # Encodes the sname field
          #
          # @return [String]
          def encode_sname
            sname.encode
          end

          # Encodes the caddr
          #
          # @return [String]
          def encode_caddr
            caddr.encode
          end

          # Decodes a Rex::Proto::Kerberos::Model::KrbCredInfo from a String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::KrbCredInfo
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            input.value.each do |val|
              case val.tag
              when 0
                self.key = decode_key(val)
              when 1
                self.prealm = decode_prealm(val)
              when 2
                self.pname = decode_pname(val)
              when 3
                self.flags = decode_flags(val)
              when 4
                self.auth_time = decode_auth_time(val)
              when 5
                self.start_time = decode_start_time(val)
              when 6
                self.end_time = decode_end_time(val)
              when 7
                self.renew_till = decode_renew_till(val)
              when 8
                self.srealm = decode_srealm(val)
              when 9
                self.sname = decode_sname(val)
              when 10
                self.caddr = decode_caddr(val)
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode KrbCredInfo SEQUENCE'
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

          # Decodes the prealm field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [String]
          def decode_prealm(input)
            input.value[0].value
          end

          # Decodes the sname field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Type::PrincipalName]
          def decode_sname(input)
            Rex::Proto::Kerberos::Model::PrincipalName.decode(input.value[0])
          end

          # Decodes the pname field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Type::PrincipalName]
          def decode_pname(input)
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

        end
      end
    end
  end
end
