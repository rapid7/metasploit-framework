unless Object.const_defined? :Enumerator
  require 'enumerator'
  unless Enumerable::Enumerator.method_defined? :next
    class Enumerable::Enumerator
      require 'backports/1.8.7/stop_iteration'

      def next
        require 'generator'
        @generator ||= ::Generator.new(self)
        raise StopIteration unless @generator.next?
        @generator.next
      end
    end
  end
end
