require 'digest'
require 'securerandom'

module Faker
  class Bitcoin < Base
    class << self
      PROTOCOL_VERSIONS = {
        main: 0,
        testnet: 111
      }.freeze

      def address
        address_for(:main)
      end

      def testnet_address
        address_for(:testnet)
      end

      protected

      def base58(str)
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        base = alphabet.size

        lv = 0
        str.split('').reverse.each_with_index { |v, i| lv += v.unpack('C')[0] * 256**i }

        ret = ''
        while lv > 0
          lv, mod = lv.divmod(base)
          ret << alphabet[mod]
        end

        npad = str.match(/^#{0.chr}*/)[0].to_s.size
        '1' * npad + ret.reverse
      end

      def address_for(network)
        version = PROTOCOL_VERSIONS.fetch(network)
        packed = version.chr + Faker::Config.random.bytes(20)
        checksum = Digest::SHA2.digest(Digest::SHA2.digest(packed))[0..3]
        base58(packed + checksum)
      end
    end
  end
end
