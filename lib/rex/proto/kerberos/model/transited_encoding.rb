# -*- coding: binary -*-

module Rex::Proto::Kerberos::Model
  # This class provides a representation of a Kerberos ticket that helps
  # a client authenticate to a service.
  class TransitedEncoding < Element

    # @return [Integer] [0] Int32 -- must be registered --
    attr_accessor :tr_type
    # @return [String] [1] OCTET STRING
    attr_accessor :contents


    # Decodes the Rex::Proto::Kerberos::Model::TransitedEncoding from an input
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
        raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode TransitedEncoding, invalid input'
      end

      self
    end

    # Encodes a Rex::Proto::Kerberos::Model::TransitedEncoding into an ASN.1 String
    #
    # @return [String]
    def encode
      to_asn1.to_der
    end

    # Encodes a Rex::Proto::Kerberos::Model::TransitedEncoding into ASN.1
    #
    # @return [OpenSSL::ASN1::ASN1Data] The TransitedEncoding ASN1Data
    def to_asn1
      elems = []
      elems << OpenSSL::ASN1::ASN1Data.new([encode_tr_type], 0, :CONTEXT_SPECIFIC)
      elems << OpenSSL::ASN1::ASN1Data.new([encode_contents], 1, :CONTEXT_SPECIFIC)

      OpenSSL::ASN1::Sequence.new(elems)
    end

    private

    # Decodes a Rex::Proto::Kerberos::Model::TicketEncPart from an String
    #
    # @param input [String] the input to decode from
    def decode_string(input)
      asn1 = OpenSSL::ASN1.decode(input)

      decode_asn1(asn1)
    end

    # Decodes a Rex::Proto::Kerberos::Model::TransitedEncoding
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
    #
    #    TransitedEncoding       ::= SEQUENCE {
    #            tr-type         [0] Int32 -- must be registered --,
    #            contents        [1] OCTET STRING
    #    }
    def decode_asn1(input)
      input.value.each do |val|
        case val.tag
        when 0  # tr-type         [0] Int32 -- must be registered --,
          self.tr_type = decode_tr_type(val)
        when 1  # contents        [1] OCTET STRING
          self.contents = decode_contents(val)
        else
          raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode TransitedEncoding SEQUENCE'
        end
      end
    end

    # Decodes the type from an OpenSSL::ASN1::ASN1Data
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [Integer]
    def decode_tr_type(input)
      input.value[0].value.to_i
    end

    # Encodes the type
    #
    # @return [OpenSSL::ASN1::Integer]
    def encode_tr_type
      bn = OpenSSL::BN.new(tr_type.to_s)
      OpenSSL::ASN1::Integer.new(bn)
    end

    # Decodes the address from an OpenSSL::ASN1::ASN1Data
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [String]
    def decode_contents(input)
      input.value[0].value
    end

    # Encodes the contents
    #
    # @return [OpenSSL::ASN1::OctetString]
    def encode_contents
      OpenSSL::ASN1::OctetString.new(contents)
    end
  end
end
