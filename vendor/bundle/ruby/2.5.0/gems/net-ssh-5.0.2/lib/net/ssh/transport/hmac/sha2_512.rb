require 'net/ssh/transport/hmac/abstract'

module Net::SSH::Transport::HMAC

  if defined?(OpenSSL::Digest::SHA512) # need openssl support
    # The SHA-512 HMAC algorithm. This has a mac and key length of 64, and
    # uses the SHA-512 digest algorithm.
    class SHA2_512 < Abstract
      mac_length   64
      key_length   64
      digest_class OpenSSL::Digest::SHA512
    end
  end
end
