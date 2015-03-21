# -*- coding: binary -*-

require 'msf/core/payload/uuid'

module Msf
  module Handler
    module ReverseHttp
      module UriChecksum

        #
        # Define 8-bit checksums for matching URLs
        # These are based on charset frequency
        #
        URI_CHECKSUM_INITW = 92 # Windows
        URI_CHECKSUM_INITN = 92 # Native (same as Windows)
        URI_CHECKSUM_INITP = 80 # Python
        URI_CHECKSUM_INITJ = 88 # Java
        URI_CHECKSUM_CONN  = 98 # Existing session

        # Mapping between checksums and modes
        URI_CHECKSUM_MODES = Hash[
          URI_CHECKSUM_INITN, :init_native,
          URI_CHECKSUM_INITP, :init_python,
          URI_CHECKSUM_INITJ, :init_java,
          URI_CHECKSUM_CONN,  :connect
        ]

        URI_CHECKSUM_MIN_LEN = 5

        # Limit how long :connect URLs are to stay within 256 bytes when including
        # the hostname, colon, port, and leading slash
        URI_CHECKSUM_CONN_MAX_LEN = 128

        URI_CHECKSUM_UUID_MIN_LEN = URI_CHECKSUM_MIN_LEN + Msf::Payload::UUID::UriLength

        # Map "random" URIs to static strings, allowing us to randomize
        # the URI sent in the first request.
        #
        # @param uri_match [String] The URI string from the HTTP request
        # @return [Hash] The attributes extracted from the URI
        def process_uri_resource(uri)

          # Ignore non-base64url characters in the URL
          uri_bare = uri.gsub(/[^a-zA-Z0-9_\-]/, '')

          # Figure out the mode based on the checksum
          uri_csum = Rex::Text.checksum8(uri_bare)

          uri_uuid = nil

          if uri_bare.length >= URI_CHECKSUM_UUID_MIN_LEN
            uri_uuid =
              Msf::Payload::UUID.payload_uuid_parse_raw(
                Rex::Text.decode_base64url(
                  uri_bare[0, Msf::Payload::UUID::UriLength]))

            # Verify the uri_uuid fields and unset everything but
            # the unique ID itself unless it looks wonky.
            if uri_uuid[:timestamp] > (Time.now.utc.to_i + (24*3600*365)) ||
               uri_uuid[:timestamp] < (Time.now.utc.to_i - (24*3600*365)) ||
               (uri_uuid[:arch].nil? && uri_uuid[:platform].nil?)
               uri_uuid = { puid: uri_uuid[:puid] }
            end
          end

          uri_mode = URI_CHECKSUM_MODES[uri_csum]

          # Return a hash of URI attributes to the caller
          {
             uri: uri_bare,
             sum: uri_csum,
            uuid: uri_uuid,
            mode: uri_mode
          }
        end

        # Create a URI that matches the :connect mode with optional UUID, Arch, and Platform
        #
        # @param uuid [Hash] An optional hash with the UUID parameters
        # @param arch [String] An optional architecture name to use if no UUID is provided
        # @param platform [String] An optional platform name to use if no UUID is provided
        # @return [String] The URI string that checksums to the given value
        def generate_uri_connect_uuid(uuid=nil, arch=nil, platform=nil)
          curl_uri_len = URI_CHECKSUM_UUID_MIN_LEN+rand(URI_CHECKSUM_CONN_MAX_LEN-URI_CHECKSUM_UUID_MIN_LEN)
          curl_prefix  = Rex::Text.encode_base64url(
            Msf::Payload::UUID.payload_uuid_generate_raw(
                   uuid: uuid[:puid],
                   arch: uuid[:arch] || arch,
               platform: uuid[:platform] || platform,
              timestamp: uuid[:timestamp] ))

          # Pad out the URI and make the checksum match :connect
          "/" + generate_uri_checksum(URI_CHECKSUM_CONN, curl_uri_len, curl_prefix)
        end

        # Create an arbitrary length URI that matches a given checksum
        #
        # @param sum [Fixnum] The checksum value that the generated URI should match
        # @param len [Fixnum] The length of the URI to generate
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

      end
    end
  end
end
