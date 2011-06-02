module RKelly
  module JS
    class Object < Base
      attr_reader :value
      class << self
        def create(*args)
          arg = args.first
          return self.new if arg.nil? || arg == :undefined
          case arg
          when true, false
            JS::Boolean.new(arg)
          when Numeric
            JS::Number.new(arg)
          when ::String
            JS::String.new(arg)
          else
            self.new(arg)
          end
        end
      end

      def initialize(*args)
        super()
        self['prototype'] = JS::ObjectPrototype.new
        self['valueOf'] = lambda { args.first || self }
        self['valueOf'].function = lambda { args.first || self }
      end
    end
  end
end
