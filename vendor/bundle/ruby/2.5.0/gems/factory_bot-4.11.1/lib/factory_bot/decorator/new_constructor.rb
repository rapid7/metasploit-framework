module FactoryBot
  class Decorator
    class NewConstructor < Decorator
      def initialize(component, build_class)
        super(component)
        @build_class = build_class
      end

      delegate :new, to: :@build_class
    end
  end
end
