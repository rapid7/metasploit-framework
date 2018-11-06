module RSpec
  module Matchers
    # Facilitates converting ruby objects to English phrases.
    module EnglishPhrasing
      # Converts a symbol into an English expression.
      #
      #     split_words(:banana_creme_pie) #=> "banana creme pie"
      #
      def self.split_words(sym)
        sym.to_s.tr('_', ' ')
      end

      # @note The returned string has a leading space except
      # when given an empty list.
      #
      # Converts an object (often a collection of objects)
      # into an English list.
      #
      #     list(['banana', 'kiwi', 'mango'])
      #     #=> " \"banana\", \"kiwi\", and \"mango\""
      #
      # Given an empty collection, returns the empty string.
      #
      #     list([]) #=> ""
      #
      def self.list(obj)
        return " #{RSpec::Support::ObjectFormatter.format(obj)}" if !obj || Struct === obj
        items = Array(obj).map { |w| RSpec::Support::ObjectFormatter.format(w) }
        case items.length
        when 0
          ""
        when 1
          " #{items[0]}"
        when 2
          " #{items[0]} and #{items[1]}"
        else
          " #{items[0...-1].join(', ')}, and #{items[-1]}"
        end
      end

      if RUBY_VERSION == '1.8.7'
        # Not sure why, but on travis on 1.8.7 we have gotten these warnings:
        # lib/rspec/matchers/english_phrasing.rb:28: warning: default `to_a' will be obsolete
        # So it appears that `Array` can trigger that (e.g. by calling `to_a` on the passed object?)
        # So here we replace `Kernel#Array` with our own warning-free implementation for 1.8.7.
        # @private
        # rubocop:disable Naming/MethodName
        def self.Array(obj)
          case obj
          when Array then obj
          else [obj]
          end
        end
        # rubocop:enable Naming/MethodName
      end
    end
  end
end
