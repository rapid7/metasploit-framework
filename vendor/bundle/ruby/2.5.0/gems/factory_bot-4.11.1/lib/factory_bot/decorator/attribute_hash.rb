module FactoryBot
  class Decorator
    class AttributeHash < Decorator
      def initialize(component, attributes = [])
        super(component)
        @attributes = attributes
      end

      def attributes
        @attributes.each_with_object({}) do |attribute_name, result|
          result[attribute_name] = send(attribute_name)
        end
      end
    end
  end
end
