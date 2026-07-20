# -*- coding: binary -*-
module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of KerberosTime
        class KerberosTime
          def self.decode(input)
            # Example decoding logic for KerberosTime
            Time.at(input.to_i)
          end

          def self.encode(time)
            # Example encoding logic for KerberosTime
            OpenSSL::ASN1::Integer.new(time.to_i)
          end
        end
      end
    end
  end
end