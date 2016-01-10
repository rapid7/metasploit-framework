# -*- coding: binary -*-
require 'net/ssh/transport/kex/diffie_hellman_group1_sha1'
require 'net/ssh/transport/kex/diffie_hellman_group_exchange_sha1'
require 'net/ssh/transport/kex/diffie_hellman_group_exchange_sha256'

module Net::SSH::Transport
  module Kex
    # Maps the supported key-exchange algorithms as named by the SSH protocol
    # to their corresponding implementors.
    MAP = {
      'diffie-hellman-group-exchange-sha1' => DiffieHellmanGroupExchangeSHA1,
      'diffie-hellman-group1-sha1'         => DiffieHellmanGroup1SHA1
    }
    if defined?(DiffieHellmanGroupExchangeSHA256)
      MAP['diffie-hellman-group-exchange-sha256'] = DiffieHellmanGroupExchangeSHA256
    end
  end
end
