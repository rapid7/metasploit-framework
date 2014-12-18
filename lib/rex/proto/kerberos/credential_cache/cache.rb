module Rex
  module Proto
    module Kerberos
      module CredentialCache
        class Cache < Element
          # Fixnum
          attr_accessor :version
          # Array
          attr_accessor :headers
          # Principal
          attr_accessor :primary_principal
          # Array
          attr_accessor :credentials

          def encode
            encoded = ''
            encoded << encode_version
            encoded << encode_headers
            encoded << encode_primary_principal
            encoded << encode_credentials
          end

          private

          def encode_version
            [version].pack('n')
          end

          def encode_headers
            headers_encoded = ''
            headers_encoded << [headers.length].pack('n')
            headers.each do |h|
              headers_encoded << h
            end

            encoded = ''
            encoded << [headers_encoded.length].pack('n')
            encoded << headers_encoded

            encoded
          end

          def encode_primary_principal
            primary_principal.encode
          end

          def encode_credentials
            encoded = ''
            credentials.each do |cred|
              encoded << cred.encode
            end
            encoded
          end
        end
      end
    end
  end
end
