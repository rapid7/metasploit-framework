unless Enumerable.method_defined? :lazy
  require 'backports/tools/arguments'
  require 'backports/1.9.1/enumerator/new'

  module Enumerable
    def lazy
      klass = Enumerator::Lazy.send :class_variable_get, :@@lazy_with_no_block # Note: class_variable_get is private in 1.8
      Enumerator::Lazy.new(klass.new(self, :each, []))
    end
  end

  class Enumerator
    class Yielder
      # Current API for Lazy Enumerator does not provide an easy way
      # to handle internal state. We "cheat" and use yielder to hold it for us.
      # A new yielder is created when generating or after a `rewind`.
      # This way we avoid issues like http://bugs.ruby-lang.org/issues/7691
      # or http://bugs.ruby-lang.org/issues/7696
      attr_accessor :backports_memo
    end

    class Lazy < Enumerator
      @@done = :__backports_lazy_enumeration_done__   # used internally to bail out of an iteration
      @@lazy_with_no_block = Struct.new(:object, :method, :args) # used internally to create lazy without block

      def initialize(obj)
        if obj.is_a?(@@lazy_with_no_block)
          @inspect_info = obj
          return super(@receiver = obj.object, @method = obj.method || :each, * @args = obj.args)
        end
        raise ArgumentError, "must supply a block" unless block_given?
        @receiver = obj
        super() do |yielder, *args|
          catch @@done do
            obj.each(*args) do |*x|
              yield yielder, *x
            end
          end
        end
      end

      alias_method :force, :to_a

      def lazy
        self
      end

      def to_enum(method = :each, *args)
        Lazy.new(@@lazy_with_no_block.new(self, method, args))
      end
      alias_method :enum_for, :to_enum

      def inspect
        suff = ''
        suff << ":#{@method}" unless @method.nil? || @method == :each
        suff << "(#{@args.inspect[1...-1]})" if @args && !@args.empty?
        "#<#{self.class}: #{@receiver.inspect}#{suff}>"
      end

      {
        :slice_before => //,
        :with_index => [],
        :cycle => [],
        :each_with_object => 42,
        :each_slice => 42,
        :each_entry => [],
        :each_cons => 42,
      }.each do |method, args|
        next unless Enumerator.method_defined? method
        unless [].lazy.send(method, *args).is_a?(Lazy) # Nothing to do if already backported, since it would use to_enum...
          module_eval <<-EOT, __FILE__, __LINE__ + 1
            def #{method}(*args)                                     # def cycle(*args)
              return to_enum(:#{method}, *args) unless block_given?  #   return to_enum(:cycle, *args) unless block_given?
              super                                                  #   super
            end                                                      # end
          EOT
        end
      end

      def chunk(*)
        super.lazy
      end if Enumerable.method_defined?(:chunk) && ![].lazy.chunk{}.is_a?(Lazy)

      def map
        raise ArgumentError, "tried to call lazy map without a block" unless block_given?
        Lazy.new(self) do |yielder, *values|
          yielder << yield(*values)
        end.__set_inspect :map
      end
      alias_method :collect, :map

      def select
        raise ArgumentError, "tried to call lazy select without a block" unless block_given?
        Lazy.new(self) do |yielder, *values|
          values = values.first unless values.size > 1
          yielder.yield values if yield values
        end.__set_inspect :select
      end
      alias_method :find_all, :select

      def reject
        raise ArgumentError, "tried to call lazy reject without a block" unless block_given?
        Lazy.new(self) do |yielder, *values|
          values = values.first unless values.size > 1
          yielder.yield(values) unless yield values
        end.__set_inspect :reject
      end

      def grep(pattern)
        if block_given?
          # Split for performance
          Lazy.new(self) do |yielder, *values|
            values = values.first unless values.size > 1
            yielder.yield(yield(values)) if pattern === values
          end
        else
          Lazy.new(self) do |yielder, *values|
            values = values.first unless values.size > 1
            yielder.yield(values) if pattern === values
          end
        end.__set_inspect :grep, [pattern]
      end

      def drop(n)
        n = Backports::coerce_to_int(n)
        Lazy.new(self) do |yielder, *values|
          data = yielder.backports_memo ||= {:remain => n}
          if data[:remain] > 0
            data[:remain] -= 1
          else
            yielder.yield(*values)
          end
        end.__set_inspect :drop, [n]
      end

      def drop_while
        raise ArgumentError, "tried to call lazy drop_while without a block" unless block_given?
        Lazy.new(self) do |yielder, *values|
          data = yielder.backports_memo ||= {:dropping => true}
          yielder.yield(*values) unless data[:dropping] &&= yield(*values)
        end.__set_inspect :drop_while
      end

      def take(n)
        n = Backports::coerce_to_int(n)
        raise ArgumentError, 'attempt to take negative size' if n < 0
        Lazy.new(n == 0 ? [] : self) do |yielder, *values|
          data = yielder.backports_memo ||= {:remain => n}
          yielder.yield(*values)
          throw @@done if (data[:remain] -= 1) == 0
        end.__set_inspect :take, [n], self
      end

      def take_while
        raise ArgumentError, "tried to call lazy take_while without a block" unless block_given?
        Lazy.new(self) do |yielder, *values|
          throw @@done unless yield(*values)
          yielder.yield(*values)
        end.__set_inspect :take_while
      end

      def flat_map
        raise ArgumentError, "tried to call lazy flat_map without a block" unless block_given?
        Lazy.new(self) do |yielder, *values|
          result = yield(*values)
          ary = Backports.is_array?(result)
          if ary || (result.respond_to?(:each) && result.respond_to?(:force))
            (ary || result).each{|x| yielder << x }
          else
            yielder << result
          end
        end.__set_inspect :flat_map
      end
      alias_method :collect_concat, :flat_map

      def zip(*args)
        return super if block_given?
        arys = args.map{ |arg| Backports.is_array?(arg) }
        if arys.all?
          # Handle trivial case of multiple array arguments separately
          # by avoiding Enumerator#next for efficiency & compatibility
          Lazy.new(self) do |yielder, *values|
            data = yielder.backports_memo ||= {:iter => 0}
            values = values.first unless values.size > 1
            yielder << arys.map{|ary| ary[data[:iter]]}.unshift(values)
            data[:iter] += 1
          end
        else
          args.each do |a|
            raise TypeError, "wrong argument type #{a.class} (must respond to :each)" unless a.respond_to? :each
          end
          Lazy.new(self) do |yielder, *values|
            enums = yielder.backports_memo ||= args.map(&:to_enum)
            values = values.first unless values.size > 1
            others = enums.map do |arg|
              begin
                arg.next
              rescue StopIteration
                nil
              end
            end
            yielder << others.unshift(values)
          end
        end.__set_inspect :zip, args
      end

      protected
      def __set_inspect(method, args = nil, receiver = nil)
        @method = method
        @args = args
        @receiver = receiver if receiver
        self
      end
    end
  end
end
