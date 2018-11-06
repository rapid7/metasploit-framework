require 'net/ssh/transport/hmac/abstract'

module Net::SSH::Transport::HMAC

  # The SHA1 HMAC algorithm. This has a mac and key length of 20, and
  # uses the SHA1 digest algorithm.
  class SHA1 < Abstract
    mac_length   20
    key_length   20
    digest_class OpenSSL::Digest::SHA1
  end

end
