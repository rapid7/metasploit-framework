module FactoryBot
  class FactoryRunner
    def initialize(name, strategy, traits_and_overrides)
      @name     = name
      @strategy = strategy

      @overrides = traits_and_overrides.extract_options!
      @traits    = traits_and_overrides
    end

    def run(runner_strategy = @strategy, &block)
      factory = FactoryBot.factory_by_name(@name)

      factory.compile

      if @traits.any?
        factory = factory.with_traits(@traits)
      end

      instrumentation_payload = {
        name: @name,
        strategy: runner_strategy,
        traits: @traits,
        overrides: @overrides,
        factory: factory
      }

      ActiveSupport::Notifications.instrument('factory_bot.run_factory', instrumentation_payload) do
        factory.run(runner_strategy, @overrides, &block)
      end
    end
  end
end
