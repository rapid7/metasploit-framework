module FactoryBot
  class Linter

    def initialize(factories, linting_strategy, factory_strategy = :create)
      @factories_to_lint = factories
      @linting_method = "lint_#{linting_strategy}"
      @factory_strategy = factory_strategy
      @invalid_factories = calculate_invalid_factories
    end

    def lint!
      if invalid_factories.any?
        raise InvalidFactoryError, error_message
      end
    end

    private

    attr_reader :factories_to_lint, :invalid_factories, :factory_strategy

    def calculate_invalid_factories
      factories_to_lint.reduce(Hash.new([])) do |result, factory|
        errors = send(@linting_method, factory)
        result[factory] |= errors unless errors.empty?
        result
      end
    end

    class FactoryError
      def initialize(wrapped_error, factory)
        @wrapped_error = wrapped_error
        @factory       = factory
      end

      def message
        message = @wrapped_error.message
        "* #{location} - #{message} (#{@wrapped_error.class.name})"
      end

      def location
        @factory.name
      end
    end

    class FactoryTraitError < FactoryError
      def initialize(wrapped_error, factory, trait_name)
        super(wrapped_error, factory)
        @trait_name = trait_name
      end

      def location
        "#{@factory.name}+#{@trait_name}"
      end
    end

    def lint_factory(factory)
      result = []
      begin
        FactoryBot.public_send(factory_strategy, factory.name)
      rescue => error
        result |= [FactoryError.new(error, factory)]
      end
      result
    end

    def lint_traits(factory)
      result = []
      factory.definition.defined_traits.map(&:name).each do |trait_name|
        begin
          FactoryBot.public_send(factory_strategy, factory.name, trait_name)
        rescue => error
          result |=
              [FactoryTraitError.new(error, factory, trait_name)]
        end
      end
      result
    end

    def lint_factory_and_traits(factory)
      errors = lint_factory(factory)
      errors |= lint_traits(factory)
      errors
    end

    def error_message
      lines = invalid_factories.map do |_factory, exceptions|
        exceptions.map(&:message)
      end.flatten

      <<-ERROR_MESSAGE.strip
The following factories are invalid:

#{lines.join("\n")}
      ERROR_MESSAGE
    end
  end
end
