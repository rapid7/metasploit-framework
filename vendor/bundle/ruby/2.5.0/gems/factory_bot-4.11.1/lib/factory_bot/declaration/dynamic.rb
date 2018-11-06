module FactoryBot
  class Declaration
    # @api private
    class Dynamic < Declaration
      def initialize(name, ignored = false, block = nil)
        super(name, ignored)
        @block = block
      end

      def ==(other)
        name == other.name &&
          ignored == other.ignored &&
          block == other.block
      end

      protected
      attr_reader :block

      private

      def build
        [Attribute::Dynamic.new(name, @ignored, @block)]
      end
    end
  end
end
