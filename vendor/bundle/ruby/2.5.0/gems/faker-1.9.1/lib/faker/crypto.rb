require 'digest'

module Faker
  class Crypto < Base
    class << self
      def md5
        Digest::MD5.hexdigest(Lorem.characters)
      end

      def sha1
        Digest::SHA1.hexdigest(Lorem.characters)
      end

      def sha256
        Digest::SHA256.hexdigest(Lorem.characters)
      end
    end
  end
end
