require 'net/ssh/transport/hmac/abstract'

module Net::SSH::Transport::HMAC

  if defined?(SHA2_512) # need openssl support
    # The SHA2-512-96 HMAC algorithm. This returns only the first 12 bytes of
    # the digest.
    class SHA2_512_96 < SHA2_512
      mac_length 12
    end
  end

end
