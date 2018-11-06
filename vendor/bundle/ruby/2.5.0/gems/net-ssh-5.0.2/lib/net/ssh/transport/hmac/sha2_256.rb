require 'net/ssh/transport/hmac/abstract'

if defined?(OpenSSL::Digest::SHA256) # need openssl support
  module Net::SSH::Transport::HMAC

    # The SHA-256 HMAC algorithm. This has a mac and key length of 32, and
    # uses the SHA-256 digest algorithm.
    class SHA2_256 < Abstract
      mac_length   32
      key_length   32
      digest_class OpenSSL::Digest::SHA256
    end

  end
end
