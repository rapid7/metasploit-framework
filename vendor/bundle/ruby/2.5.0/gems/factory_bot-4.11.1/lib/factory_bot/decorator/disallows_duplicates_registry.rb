module FactoryBot
  class Decorator
    class DisallowsDuplicatesRegistry < Decorator
      def register(name, item)
        if registered?(name)
          raise DuplicateDefinitionError, "#{@component.name} already registered: #{name}"
        else
          @component.register(name, item)
        end
      end
    end
  end
end
