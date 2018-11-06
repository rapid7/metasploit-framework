require 'net/ssh/transport/hmac/abstract'

module Net::SSH::Transport::HMAC

  # The "none" algorithm. This has a key and mac length of 0.
  class None < Abstract
    key_length 0
    mac_length 0

    def digest(data)
      ""
    end
  end

end
