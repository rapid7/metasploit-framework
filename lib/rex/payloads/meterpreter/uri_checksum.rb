# -*- coding: binary -*-
require 'msf/core/payload/uuid'

module Rex
  module Payloads
    module Meterpreter
      module UriChecksum

        #
        # Define 8-bit checksums for matching URLs
        # These are based on charset frequency
        #
        URI_CHECKSUM_INITW      = 92 # Windows
        URI_CHECKSUM_INITN      = 92 # Native (same as Windows)
        URI_CHECKSUM_INITP      = 80 # Python
        URI_CHECKSUM_INITJ      = 88 # Java
        URI_CHECKSUM_CONN       = 98 # Existing session
        URI_CHECKSUM_INIT_CONN  = 95 # New stageless session

        # Mapping between checksums and modes
        URI_CHECKSUM_MODES = Hash[
          URI_CHECKSUM_INITN,      :init_native,
          URI_CHECKSUM_INITP,      :init_python,
          URI_CHECKSUM_INITJ,      :init_java,
          URI_CHECKSUM_INIT_CONN,  :init_connect,
          URI_CHECKSUM_CONN,       :connect
        ]

        URI_CHECKSUM_MIN_LEN = 5

        # Limit how long :connect URLs are to stay within 256 bytes when including
        # the hostname, colon, port, and leading slash
        URI_CHECKSUM_CONN_MAX_LEN = 128

        URI_CHECKSUM_UUID_MIN_LEN = URI_CHECKSUM_MIN_LEN + Msf::Payload::UUID::UriLength

        # Map "random" URIs to static strings, allowing us to randomize
        # the URI sent in the first request.
        #
        # @param uri [String] The URI string from the HTTP request
        # @return [Hash] The attributes extracted from the URI
        def process_uri_resource(uri)

          # Ignore non-base64url characters in the URL
          uri_bare = uri.gsub(/[^a-zA-Z0-9_\-]/, '')

          # Figure out the mode based on the checksum
          uri_csum = Rex::Text.checksum8(uri_bare)

          # Extract the UUID if the URI is long enough
          uri_uuid = nil
          if uri_bare.length >= URI_CHECKSUM_UUID_MIN_LEN
            uri_uuid = Msf::Payload::UUID.new(uri: uri_bare)
          end

          uri_mode = URI_CHECKSUM_MODES[uri_csum]

          # Return a hash of URI attributes
          { uri: uri_bare, sum: uri_csum, uuid: uri_uuid, mode: uri_mode }
        end

        # Create a URI that matches the specified checksum and payload uuid
        #
        # @param sum [Integer] A checksum mode value to use for the generated url
        # @param uuid [Msf::Payload::UUID] A valid UUID object
        # @param len [Integer] An optional URI length value, including the leading slash
        # @return [String] The URI string for connections
        def generate_uri_uuid(sum, uuid, len=nil)
          curl_uri_len = URI_CHECKSUM_UUID_MIN_LEN + rand(URI_CHECKSUM_CONN_MAX_LEN - URI_CHECKSUM_UUID_MIN_LEN)
          curl_prefix  = uuid.to_uri

          if len
            # Subtract a byte to take into account the leading /
            curl_uri_len = len - 1
          end

          if curl_uri_len < URI_CHECKSUM_UUID_MIN_LEN
            raise ArgumentError, "Length must be #{URI_CHECKSUM_UUID_MIN_LEN+1} bytes or greater"
          end

          # Pad out the URI and make the checksum match the specified sum
          "/" + generate_uri_checksum(sum, curl_uri_len, curl_prefix)
        end

        # Create an arbitrary length URI that matches a given checksum
        #
        # @param sum [Integer] The checksum value that the generated URI should match
        # @param len [Integer] The length of the URI to generate
        # @param prefix [String] The optional prefix to use to build the URI
        # @return [String] The URI string that checksums to the given value
        def generate_uri_checksum(sum, len=5, prefix="")
          # Lengths shorter than 4 bytes are unable to match all possible checksums
          # Lengths of exactly 4 are relatively slow to find for high checksum values
          # Lengths of 5 or more bytes find a matching checksum fairly quickly (~80ms)
          if len < URI_CHECKSUM_MIN_LEN
            raise ArgumentError, "Length must be #{URI_CHECKSUM_MIN_LEN} bytes or greater"
          end

          gen_len = len-prefix.length
          if gen_len < URI_CHECKSUM_MIN_LEN
            raise ArgumentError, "Prefix must be at least {URI_CHECKSUM_MIN_LEN} bytes smaller than total length"
          end

          # Brute force a matching checksum for shorter URIs
          if gen_len < 40
            loop do
              uri = prefix + Rex::Text.rand_text_base64url(gen_len)
              return uri if Rex::Text.checksum8(uri) == sum
            end
          end

          # The rand_text_base64url() method becomes a bottleneck at around 40 bytes
          # Calculating a static prefix flattens out the average runtime for longer URIs
          prefix << Rex::Text.rand_text_base64url(gen_len-20)

          loop do
            uri = prefix + Rex::Text.rand_text_base64url(20)
            return uri if Rex::Text.checksum8(uri) == sum
          end
        end

        # Return the numerical checksum for a given mode symbol
        #
        # @param mode [Symbol] The mode symbol to lookup (:connect, :init_native, :init_python, :init_java)
        # @return [Integer] The URI checksum value corresponding with the mode
        def uri_checksum_lookup(mode)
          sum = URI_CHECKSUM_MODES.keys.select{|ksum| URI_CHECKSUM_MODES[ksum] == mode}.first
          unless sum
            raise ArgumentError, "Unknown checksum mode: #{mode}"
          end
          sum
        end
      end
    end
  end
end
