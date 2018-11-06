module FactoryBot

  # Sequences are defined using sequence within a FactoryBot.define block.
  # Sequence values are generated using next.
  # @api private
  class Sequence
    attr_reader :name

    def initialize(name, *args, &proc)
      @name    = name
      @proc    = proc

      options  = args.extract_options!
      @value   = args.first || 1
      @aliases = options.fetch(:aliases) { [] }

      if !@value.respond_to?(:peek)
        @value = EnumeratorAdapter.new(@value)
      end
    end

    def next(scope = nil)
      if @proc && scope
        scope.instance_exec(value, &@proc)
      elsif @proc
        @proc.call(value)
      else
        value
      end
    ensure
      increment_value
    end

    def names
      [@name] + @aliases
    end

    def rewind
      @value.rewind
    end

    private

    def value
      @value.peek
    end

    def increment_value
      @value.next
    end

    class EnumeratorAdapter
      def initialize(value)
        @first_value = value
        @value = value
      end

      def peek
        @value
      end

      def next
        @value = @value.next
      end

      def rewind
        @value = @first_value
      end
    end
  end
end
