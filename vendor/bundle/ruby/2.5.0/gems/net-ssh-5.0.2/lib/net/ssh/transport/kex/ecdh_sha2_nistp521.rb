module Net 
  module SSH 
    module Transport 
      module Kex

        # A key-exchange service implementing the "ecdh-sha2-nistp521"
        # key-exchange algorithm. (defined in RFC 5656)
        class EcdhSHA2NistP521 < EcdhSHA2NistP256
          def digester
            OpenSSL::Digest::SHA512
          end

          def curve_name
            OpenSSL::PKey::EC::CurveNameAlias['nistp521']
          end
        end
      end
    end
  end
end
