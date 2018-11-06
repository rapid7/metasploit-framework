module FactoryBot
  class DefinitionHierarchy
    def callbacks
      FactoryBot.callbacks
    end

    def constructor
      FactoryBot.constructor
    end

    def to_create
      FactoryBot.to_create
    end

    def self.build_from_definition(definition)
      build_to_create(&definition.to_create)
      build_constructor(&definition.constructor)
      add_callbacks definition.callbacks
    end

    def self.add_callbacks(callbacks)
      if callbacks.any?
        define_method :callbacks do
          super() + callbacks
        end
      end
    end
    private_class_method :add_callbacks

    def self.build_constructor(&block)
      if block
        define_method(:constructor) do
          block
        end
      end
    end
    private_class_method :build_constructor

    def self.build_to_create(&block)
      if block
        define_method(:to_create) do
          block
        end
      end
    end
    private_class_method :build_to_create
  end
end
