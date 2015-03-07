# -*- coding: binary -*-
module Msf
  module Handler
    module ReverseHttp
      module UriChecksum

        #
        # Define 8-bit checksums for matching URLs
        # These are based on charset frequency
        #
        URI_CHECKSUM_INITW = 92 # Windows
        URI_CHECKSUM_INITP = 80 # Python
        URI_CHECKSUM_INITJ = 88 # Java
        URI_CHECKSUM_CONN  = 98

        # Map "random" URIs to static strings, allowing us to randomize
        # the URI sent in the first request.
        #
        # @param uri_match [String] The URI string to convert back to the original static value
        # @return [String] The static URI value derived from the checksum
        def process_uri_resource(uri_match)

          # This allows 'random' strings to be used as markers for
          # the INIT and CONN request types, based on a checksum
          uri_strip, uri_conn = uri_match.split('_', 2)
          uri_strip.sub!(/^\//, '')
          uri_check = Rex::Text.checksum8(uri_strip)

          # Match specific checksums and map them to static URIs
          case uri_check
            when URI_CHECKSUM_INITW
              uri_match = "/INITM"
            when URI_CHECKSUM_INITP
              uri_match = "/INITPY"
            when URI_CHECKSUM_INITJ
              uri_match = "/INITJM"
            when URI_CHECKSUM_CONN
              uri_match = "/CONN_" + ( uri_conn || Rex::Text.rand_text_alphanumeric(16) )
          end

          uri_match
        end

        # Create a URI that matches a given checksum
        #
        # @param sum [Fixnum] The checksum value you are trying to create a URI for
        # @return [String] The URI string that checksums to the given value
        def generate_uri_checksum(sum, len=5)
          # Funny enough, this was more efficient than calculating checksum offsets
          loop do
            uri = Rex::Text.rand_text_alphanumeric(len)
            return uri if Rex::Text.checksum8(uri) == sum
          end
        end

      end
    end
  end
end
