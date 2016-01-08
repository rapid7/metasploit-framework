require 'net/ssh/transport/kex/diffie_hellman_group_exchange_sha1'

module Net::SSH::Transport::Kex
  if defined?(OpenSSL::Digest::SHA256)
    # A key-exchange service implementing the
    # "diffie-hellman-group-exchange-sha256" key-exchange algorithm.
    class DiffieHellmanGroupExchangeSHA256 < DiffieHellmanGroupExchangeSHA1
      def initialize(*args)
        super(*args)

        @digester = OpenSSL::Digest::SHA256
      end
    end
  end
end
