module Faker
  class Source < Base
    class << self
      def hello_world(lang = :ruby)
        fetch("source.hello_world.#{lang}")
      end

      def print(str: 'some string', lang: :ruby)
        code = fetch("source.print.#{lang}")
        code.gsub('faker_string_to_print', str)
      end

      def print_1_to_10(lang = :ruby)
        fetch("source.print_1_to_10.#{lang}")
      end
    end
  end
end
