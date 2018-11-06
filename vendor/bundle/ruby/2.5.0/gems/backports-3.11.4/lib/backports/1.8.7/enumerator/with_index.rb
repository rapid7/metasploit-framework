unless Object.const_defined? :Enumerator
  require 'enumerator'
  unless Enumerable::Enumerator.method_defined? :with_index
    class Enumerable::Enumerator
      def with_index(offset = 0)
        return to_enum(:with_index, offset) unless block_given?
        each do |*args|
          yield args.size == 1 ? args[0] : args, offset
          offset += 1
        end
      end
    end
  end
end
