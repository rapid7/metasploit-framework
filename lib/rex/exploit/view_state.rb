# -*- coding: binary -*-

module Rex
  module Exploit
    class ViewState
      class Error < Rex::RuntimeError
      end

      def self.decode_viewstate(encoded_viewstate, algo: 'sha1')
        viewstate = Rex::Text.decode_base64(encoded_viewstate)

        unless Rex::Text.encode_base64(viewstate) == encoded_viewstate
          raise Error.new('Could not decode ViewState')
        end

        hmac_len = OpenSSL::Digest.new(algo).digest_length

        if (data = viewstate[0...-hmac_len]).empty?
          data = nil
        end

        hmac = viewstate[-hmac_len..-1]
        unless hmac&.length == hmac_len
          raise Error.new('Could not decode ViewState')
        end

        { data: data, hmac: hmac }
      end

      def self.generate_viewstate(data, extra: '', algo: 'sha1', key: '')
        # Generate ViewState HMAC from known values and validation key
        hmac = generate_viewstate_hmac(data + extra, algo: algo, key: key)

        # Append HMAC to provided data and Base64-encode the whole shebang
        Rex::Text.encode_base64(data + hmac)
      end

      def self.generate_viewstate_hmac(data, algo: 'sha1', key: '')
        OpenSSL::HMAC.digest(algo, key, data)
      end

      def self.is_viewstate_valid?(encoded_viewstate, extra: '', algo: 'sha1', key: '')
        viewstate = decode_viewstate(encoded_viewstate)

        unless viewstate[:data]
          raise Error.new('Could not retrieve ViewState data')
        end

        unless (their_hmac = viewstate[:hmac])
          raise Error.new('Could not retrieve ViewState HMAC')
        end

        our_hmac = generate_viewstate_hmac(
          viewstate[:data] + extra,
          algo: algo,
          key: key
        )

        # Do we have what it takes?
        our_hmac == their_hmac
      end

      class << self
        alias_method :can_sign_viewstate?, :is_viewstate_valid?
      end
    end
  end
end
