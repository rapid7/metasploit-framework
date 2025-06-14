# -*- coding: binary -*-

# This class provides a representation for Kerberos pre authenticated
# data
#   https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.5
#   HostAddress     ::= SEQUENCE  {
#           addr-type       [0] Int32,
#           address         [1] OCTET STRING
#    }
class Rex::Proto::Kerberos::Model::HostAddress < Rex::Proto::Kerberos::Model::Element
  # @!attribute type
  #   @return [Rex::Proto::Kerberos::Model::AddressType,Integer] The address addr-type
  attr_accessor :type
  # @!attribute address
  #   @return [String] The address value
  attr_accessor :address

  # Decodes a Rex::Proto::Kerberos::Model::HostAddress
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
      raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode HostAddress, invalid input'
    end

    self
  end

  # Encodes a Rex::Proto::Kerberos::Model::HostAddress into an ASN.1 String
  #
  # @return [String]
  def encode
    to_asn1.to_der
  end

  # Encodes a Rex::Proto::Kerberos::Model::HostAddress into ASN.1
  #
  # @return [OpenSSL::ASN1::ASN1Data] The HostAddress ASN1Data
  def to_asn1
    type_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_type], 0, :CONTEXT_SPECIFIC)
    address_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_address], 1, :CONTEXT_SPECIFIC)
    seq = OpenSSL::ASN1::Sequence.new([type_asn1, address_asn1])

    seq
  end

  private

  # Encodes the type
  #
  # @return [OpenSSL::ASN1::Integer]
  def encode_type
    int_bn = OpenSSL::BN.new(type.to_s)
    int = OpenSSL::ASN1::Integer.new(int_bn)

    int
  end

  # Encodes the address
  #
  # @return [OpenSSL::ASN1::OctetString]
  def encode_address
    OpenSSL::ASN1::OctetString.new(address)
  end

  # Decodes a Rex::Proto::Kerberos::Model::HostAddress
  #
  # @param input [String] the input to decode from
  def decode_string(input)
    asn1 = OpenSSL::ASN1.decode(input)

    decode_asn1(asn1)
  end

  # Decodes a Rex::Proto::Kerberos::Model::HostAddress from an
  # OpenSSL::ASN1::Sequence
  #
  # @param input [OpenSSL::ASN1::Sequence] the input to decode from
  def decode_asn1(input)
    seq_values = input.value
    self.type  = decode_asn1_type(seq_values[0])
    self.address = decode_asn1_address(seq_values[1])
  end

  # Decodes the type from an OpenSSL::ASN1::ASN1Data
  #
  # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
  # @return [Integer]
  def decode_asn1_type(input)
    input.value[0].value.to_i
  end

  # Decodes the address from an OpenSSL::ASN1::ASN1Data
  #
  # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
  # @return [Integer]
  def decode_asn1_address(input)
    input.value[0].value
  end
end
