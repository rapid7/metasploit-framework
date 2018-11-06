module FactoryBot
  class Attribute
    # @api private
    class Static < Attribute
      def initialize(name, value, ignored)
        super(name, ignored)
        @value = value
      end

      def to_proc
        value = @value
        -> { value }
      end
    end
  end
end
