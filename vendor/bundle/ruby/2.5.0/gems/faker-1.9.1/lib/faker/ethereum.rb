module Faker
  class Ethereum < Base
    class << self
      def address
        hex_alphabet = '0123456789abcdef'
        var = '0x'
        40.times { var << sample(shuffle(hex_alphabet.split(''))) }
        var
      end
    end
  end
end
