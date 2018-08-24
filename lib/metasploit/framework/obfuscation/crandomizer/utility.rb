require 'metasm'
require 'securerandom'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer

        class Utility

          # Returns a random number.
          #
          # @return [Integer]
          def self.rand_int
            SecureRandom.random_number(100000000)
          end

          # Returns a random string.
          #
          # @return [String]
          def self.rand_string
            SecureRandom.hex
          end

          # Returns a Metasm parser.
          #
          # @param code [String] The C code to parse.
          # @return [Metasm::C::Parser]
          def self.parse(code)
            parser = Metasm::C::Parser.new
            parser.allow_bad_c = true
            parser.parse(code)
            parser
          end
        end

      end
    end
  end
end