module Net 
  module SSH 
    module Transport 
      module Kex

        # A key-exchange service implementing the "ecdh-sha2-nistp256"
        # key-exchange algorithm. (defined in RFC 5656)
        class EcdhSHA2NistP384 < EcdhSHA2NistP256
          def digester
            OpenSSL::Digest::SHA384
          end

          def curve_name
            OpenSSL::PKey::EC::CurveNameAlias['nistp384']
          end
        end
      end
    end
  end
end
