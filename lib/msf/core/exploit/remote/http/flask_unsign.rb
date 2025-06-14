require 'base64'
require 'json'
require 'openssl'
require 'zlib'

module Msf
  class Exploit
    class Remote
      module HTTP
        module FlaskUnsign
          # This module is a ruby implementation of https://github.com/Paradoxis/Flask-Unsign which can be used to
          # decode, and re-sign cookies

          def self.base64_encode(value)
            Base64.urlsafe_encode64(value).gsub(/=+$/, '')
          end

          class URLSafeSigner
            DEFAULT_SEPARATOR = '.'

            def initialize(secret_key, salt, separator: DEFAULT_SEPARATOR)
              @secret_key = secret_key
              @salt = salt
              @separator = separator
            end

            def derive_key
              hmac = OpenSSL::HMAC.new(@secret_key, OpenSSL::Digest.new('SHA1'))
              hmac.update(@salt)
              hmac.digest
            end

            def get_signature(value)
              hmac = OpenSSL::HMAC.new(derive_key, OpenSSL::Digest.new('SHA1'))
              hmac.update(value)
              FlaskUnsign.base64_encode(hmac.digest)
            end
          end

          class URLSafeTimedSigner < URLSafeSigner
            def get_timestamp
              Time.now.to_f
            end

            def timestamp_to_datetime(ts)
              Time.at(ts)
            end

            def sign(value)
              timestamp = [get_timestamp].pack('Q>')
              timestamp.delete_prefix!("\x00".b) while timestamp.start_with?("\x00".b)
              timestamp = FlaskUnsign.base64_encode(timestamp)
              value = value + @separator + timestamp
              value + @separator + get_signature(value)
            end

            def valid?(value)
              value, _, signature = value.rpartition(@separator)
              value, _, timestamp = value.rpartition(@separator)
              signature == get_signature(value + @separator + timestamp)
            end
          end

          # This emulates the default cookie-based session storage used by the latest version of Flask as of the time of
          # this writing (2023-09-07).
          # See: https://github.com/pallets/flask/blob/8037487165a196015a646de25cbce6d0351c8fc4/src/flask/sessions.py#L276
          module Session
            DEFAULT_SALT = 'cookie-session'

            def self.decode(value)
              parse(value)[:deserialized]
            end

            def self.parse(value)
              compressed = value.start_with?('.')
              value = value[1..] if compressed

              serialized, signature = value.split('.', 3)
              value = Base64.urlsafe_decode64(serialized)
              value = Zlib::Inflate.inflate(value) if compressed
              { compressed: compressed, signature: signature, deserialized: JSON.parse(value), serialized: serialized }
            end

            def self.sign(value, secret, salt: DEFAULT_SALT)
              json = JSON.dump(value)
              signer = URLSafeTimedSigner.new(secret, salt)
              signer.sign(FlaskUnsign.base64_encode(json).strip)
            end

            def self.valid?(value, secret, salt: DEFAULT_SALT)
              signer = URLSafeTimedSigner.new(secret, salt)
              signer.valid?(value)
            end
          end
        end
      end
    end
  end
end
