module FactoryBot
  class Declaration
    # @api private
    class Static < Declaration
      def initialize(name, value, ignored = false)
        super(name, ignored)
        @value = value
      end

      def ==(other)
        name == other.name &&
          value == other.value &&
          ignored == other.ignored
      end

      protected
      attr_reader :value

      private

      def build
        [Attribute::Static.new(name, @value, @ignored)]
      end
    end
  end
end
