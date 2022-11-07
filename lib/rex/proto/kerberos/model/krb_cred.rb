# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a Kerberos KRB-CRED
        # message definition.
        class KrbCred < Element
          # @!attribute pvno
          #   @return [Integer] The protocol version number
          attr_accessor :pvno
          # @!attribute msg_type
          #   @return [Integer] The type of a protocol message
          attr_accessor :msg_type
          # @!attribute tickets
          #   @return [Array<Rex::Proto::Kerberos::Model::Ticket>] Tickets encapsulated in this message
          attr_accessor :tickets
          # @!attribute enc_part
          #   @return [Rex::Proto::Kerberos::Model::EncryptedData] Encrypted KRB-CRED blob
          attr_accessor :enc_part

          def ==(other)
            pvno == other.pvno &&
              msg_type == other.msg_type &&
              tickets == other.tickets &&
              enc_part == other.enc_part
          end

          # Decodes the Rex::Proto::Kerberos::Model::KrbCred from an input
          #
          # @param input [String, OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [self] if decoding succeeds
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode(input)
            case input
            when String
              decode_string(input)
            when OpenSSL::ASN1::Sequence
              decode_asn1(input)
            else
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode KrbCred, invalid input'
            end

            self
          end

          # Rex::Proto::Kerberos::Model::KrbCred encoding isn't supported
          #
          # @raise [NotImplementedError]
          def encode
            elems = []
            elems << OpenSSL::ASN1::ASN1Data.new([encode_pvno], 0, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_msg_type], 1, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_tickets], 2, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_enc_part], 3, :CONTEXT_SPECIFIC)

            seq = OpenSSL::ASN1::Sequence.new(elems)
            seq_asn1 = OpenSSL::ASN1::ASN1Data.new([seq], KRB_CRED, :APPLICATION)

            seq_asn1.to_der
          end

          # Loads a KrbCred from a kirbi file
          # @param [String] file_path the path to load the file from
          # @return [Rex::Proto::Kerberos::Model::KrbCred]
          def self.load_credential_from_file(file_path)
            unless File.readable?(file_path.to_s)
              raise ::ArgumentError, "Failed to load kirbi file '#{file_path}'"
            end

            decode(File.binread(file_path))
          end

          # Saves a KrbCred to a kirbi file
          # @param [String] file_path the path to save the file to
          # @return [Integer] The length written
          def save_credential_to_file(file_path)
            File.binwrite(file_path, encode)
          end

          private

          # Encodes the pvno
          #
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError]
          def encode_pvno
            bn = OpenSSL::BN.new(pvno.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          rescue OpenSSL::ASN1::ASN1Error
            raise Rex::Proto::Kerberos::Model::Error::KerberosDecodingError
          end

          # Encodes the msg_type field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_msg_type
            bn = OpenSSL::BN.new(msg_type.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the ticket field
          #
          # @return [OpenSSL::ASN1::Sequence]
          def encode_tickets
            encoded = tickets.map(&:encode)
            seq = OpenSSL::ASN1::Sequence.new(encoded)
          end

          # Encodes the enc_part field
          #
          # @return [String]
          def encode_enc_part
            encoded = enc_part.encode
          end

          # Decodes a Rex::Proto::Kerberos::Model::KrbCred
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::KrbCred from an
          # OpenSSL::ASN1Data
          #
          # @param input [OpenSSL::ASN1Data] the input to decode from
          def decode_asn1(input)
            input.value[0].value.each do |val|
              case val.tag
              when 0
                self.pvno = decode_pvno(val)
              when 1
                self.msg_type = decode_msg_type(val)
              when 2
                self.tickets = decode_tickets(val)
              when 3
                self.enc_part = decode_enc_part(val)
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, "Failed to decode KrbCred (#{val.tag})"
              end
            end
          end

          # Decodes the pvno from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_pvno(input)
            input.value[0].value.to_i
          end

          # Decodes the msg_type from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_msg_type(input)
            input.value[0].value.to_i
          end

          # Decodes the tickets from an OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          # @return [Array<Rex::Proto::Kerberos::Model::Tickets>]
          def decode_tickets(input)
            tickets = []
            input.value[0].value.each do |val|
              tickets << Rex::Proto::Kerberos::Model::Ticket.decode(val)
            end
            tickets
          end

          # Decodes the enc_part
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Model::EncryptedData]
          def decode_enc_part(input)
            Rex::Proto::Kerberos::Model::EncryptedData.decode(input.value[0])
          end
        end
      end
    end
  end
end
