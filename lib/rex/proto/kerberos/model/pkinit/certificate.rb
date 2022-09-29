# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class Certificate

            attr_accessor :value

            def initialize(value={})
              self.value = value
            end

            def to_der
              self.value[:openssl_certificate].to_der
            end

            def parse!(str, ber: false)
              self.value[:openssl_certificate] = OpenSSL::X509::Certificate.new(str)
              to_der.length
            end

          end
        end
      end
    end
  end
end
