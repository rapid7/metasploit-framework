# -*- coding: binary -*-
require 'rasn1'

module Rex::Proto::CryptoAsn1::Types
  class RASN1::Model
    def self.bmp_string(name, options = {})
      custom_primitive_type_for(name, RASN1::Types::BmpString, options)
    end

    def self.teletex_string(name, options = {})
      strict_encoding = options.fetch(:strict_encoding, true)
      options.delete(:strict_encoding)

      if strict_encoding
        raise NotImplementedError.new('The ITU T.61 codec is not available.')

        custom_primitive_type_for(name, TeletexString, options)
      else
        custom_primitive_type_for(name, TeletexString::Permissive, options)
      end
    end

    def self.universal_string(name, options = {})
      custom_primitive_type_for(name, UniversalString, options)
    end

    def self.custom_primitive_type_for(name, clazz, options = {})
      options.merge!(name: name)
      proc = proc do |opts|
        clazz.new(options.merge(opts))
      end
      @root = Elem.new(name, proc, nil)
    end

    private_class_method :custom_primitive_type_for
  end

  class TeletexString < RASN1::Types::OctetString
    ID = 20

    def self.type
      'TeletexString'
    end

    ENCODING = 'ITU-T.61'.freeze

    # Technically this type should be using T.61 encoding, however some libraries
    # such as OpenSSL use this type to label strings encoded with ISO-8859-1.
    # See:
    #   * https://pike.lysator.liu.se/generated/manual/modref/ex/7.8_3A_3A/Standards/ASN1/Types/TeletexString.html
    #   * https://github.com/wbond/asn1crypto/blob/fad689f2072e405317436c8bf7f6609ba183a060/asn1crypto/x509.py#L461-L465
    class Permissive < TeletexString
      ENCODING = 'ISO-8859-1'.freeze
    end

    private

    def value_to_der
      @value.to_s.dup.encode(self.class::ENCODING).b
    end

    def der_to_value(der, ber: false)
      super
      @value = der.dup.force_encoding(self.class::ENCODING)
    end
  end

  class UniversalString < RASN1::Types::OctetString
    ID = 28

    def self.type
      'UniversalString'
    end

    private

    def value_to_der
      @value.to_s.dup.encode('UTF-32BE').b
    end

    def der_to_value(der, ber: false)
      super
      @value = der.dup.force_encoding('UTF-32BE')
    end
  end
end
