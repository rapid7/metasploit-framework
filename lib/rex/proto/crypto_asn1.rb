# -*- coding: binary -*-
require 'rasn1'

module Rex::Proto::CryptoAsn1
  class RASN1::Model
    def self.bmp_string(name, options = {})
      custom_primitive_type_for(name, BmpString, options)
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

  class BmpString < RASN1::Types::OctetString
    ID = 30

    # Get ASN.1 type
    # @return [String]
    def self.type
      'BmpString'
    end

    private

    def value_to_der
      @value.to_s.dup.encode('UTF-16BE').b
    end

    def der_to_value(der, ber: false)
      super
      @value = der.dup.force_encoding('UTF-16BE')
    end
  end

  # see: [[MS-WCCE]: 2.2.2.7.10 szENROLLMENT_NAME_VALUE_PAIR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/92f07a54-2889-45e3-afd0-94b60daa80ec)
  class EnrollmentNameValuePair < RASN1::Model
    sequence :enrollment_name_value_pair, content: [
      bmp_string(:name),
      bmp_string(:value)
    ]
  end
end
