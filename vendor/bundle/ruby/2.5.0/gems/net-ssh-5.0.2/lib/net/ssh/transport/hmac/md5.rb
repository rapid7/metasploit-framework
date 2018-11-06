require 'net/ssh/transport/hmac/abstract'

module Net::SSH::Transport::HMAC

  # The MD5 HMAC algorithm.
  class MD5 < Abstract
    mac_length   16
    key_length   16
    digest_class OpenSSL::Digest::MD5
  end

end
