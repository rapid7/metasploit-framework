require 'net/ssh/transport/hmac/abstract'

module Net::SSH::Transport::HMAC

  # The RIPEMD-160 HMAC algorithm. This has a mac and key length of 20, and
  # uses the RIPEMD-160 digest algorithm.
  class RIPEMD160 < Abstract
    mac_length   20
    key_length   20
    digest_class OpenSSL::Digest::RIPEMD160
  end

end
