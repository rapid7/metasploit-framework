module Rex
  module Proto
    module Kerberos
      module CredentialCache
=begin
ccache {
          uint16_t file_format_version; /* 0x0504 */
          uint16_t headerlen;           /* only if version is 0x0504 */
          header headers[];             /* only if version is 0x0504 */
          principal primary_principal;
          credential credentials[*];
};
=end
        class Cache < Element
          attr_accessor :primary_principal
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
            [0x0504].pack('n')
          end

          def encode_headers
            header = "\x00\x01\x00\x08\xff\xff\xff\xff\x00\x00\x00\x00"
            encoded = ''
            encoded << [header.length].pack('n')
            encoded << header

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
