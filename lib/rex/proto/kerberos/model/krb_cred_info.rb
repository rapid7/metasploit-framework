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

          # Not Implemented
          def decode(input)
            raise ::NotImplementedError, 'KrbCredInfo encoding not supported'
          end

          def encode
            elems = []
            elems << OpenSSL::ASN1::ASN1Data.new([encode_key], 0, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_prealm], 1, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_pname], 2, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_flags], 3, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_auth_time], 4, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_start_time], 5, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_end_time], 6, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_renew_till], 7, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_srealm], 8, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_sname], 9, :CONTEXT_SPECIFIC)
            seq = OpenSSL::ASN1::Sequence.new(elems)
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
        end
      end
    end
  end
end
