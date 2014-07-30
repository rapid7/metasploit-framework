# -*- coding: binary -*-
module Msf
  module Handler
    module ReverseHttp
      module UriChecksum

        #
        # Define 8-bit checksums for matching URLs
        # These are based on charset frequency
        #
        URI_CHECKSUM_INITW = 92
        URI_CHECKSUM_INITJ = 88
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
            when URI_CHECKSUM_INITJ
              uri_match = "/INITJM"
            when URI_CHECKSUM_CONN
              uri_match = "/CONN_" + ( uri_conn || Rex::Text.rand_text_alphanumeric(16) )
          end

          uri_match
        end

        # Create a URI that matches a given checksum
        #
        # @param sum [Fixnum] The checksum value you are trying to create a URI for. Must be between 0 and 255 inclusive
        # @param length [Fixnum] The requested length of the string to be returned. Must be > 1.
        # @return [String] The URI string that checksums to the given value
        def generate_uri_checksum(sum, length=4)
          raise ArgumentError, "sum must be a number >= 0 and <= 255" unless sum.is_a? Fixnum and sum >= 0 and sum <= 255
          raise ArgumentError, "length must be a number >= 1" unless length.is_a? Fixnum and length >= 1
          chk = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
          indices = (0..length-1).collect{ rand(chk.length) }
          
          loop do
            uri = indices.collect{ |x| chk[x] }.join("")
            return uri if Rex::Text.checksum8(uri) == sum
            
            # Increment indices within some lexicographic ordering
            carry = 1
            for i in (0..indices.length-1) do
              carry, indices[i] = (indices[i] + carry).divmod(chk.length)
            end
          end
        end

      end
    end
  end
end
