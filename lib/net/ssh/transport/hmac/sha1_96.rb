require 'net/ssh/transport/hmac/sha1'

module Net::SSH::Transport::HMAC

  # The SHA1-96 HMAC algorithm. This returns only the first 12 bytes of
  # the digest.
  class SHA1_96 < SHA1
    mac_length 12
  end

end
