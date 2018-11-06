require 'net/ssh/transport/kex/diffie_hellman_group1_sha1'
require 'net/ssh/transport/kex/diffie_hellman_group14_sha1'
require 'net/ssh/transport/kex/diffie_hellman_group_exchange_sha1'
require 'net/ssh/transport/kex/diffie_hellman_group_exchange_sha256'

module Net::SSH::Transport
  module Kex
    # Maps the supported key-exchange algorithms as named by the SSH protocol
    # to their corresponding implementors.
    MAP = {
      'diffie-hellman-group-exchange-sha1' => DiffieHellmanGroupExchangeSHA1,
      'diffie-hellman-group1-sha1'         => DiffieHellmanGroup1SHA1,
      'diffie-hellman-group14-sha1'        => DiffieHellmanGroup14SHA1
    }
    MAP['diffie-hellman-group-exchange-sha256'] = DiffieHellmanGroupExchangeSHA256 if defined?(DiffieHellmanGroupExchangeSHA256)
    if defined?(OpenSSL::PKey::EC)
      require 'net/ssh/transport/kex/ecdh_sha2_nistp256'
      require 'net/ssh/transport/kex/ecdh_sha2_nistp384'
      require 'net/ssh/transport/kex/ecdh_sha2_nistp521'

      MAP['ecdh-sha2-nistp256'] = EcdhSHA2NistP256
      MAP['ecdh-sha2-nistp384'] = EcdhSHA2NistP384
      MAP['ecdh-sha2-nistp521'] = EcdhSHA2NistP521
    end
  end
end
