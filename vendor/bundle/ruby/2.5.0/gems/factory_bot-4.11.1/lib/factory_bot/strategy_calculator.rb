module FactoryBot
  # @api private
  class StrategyCalculator
    def initialize(name_or_object)
      @name_or_object = name_or_object
    end

    def strategy
      if strategy_is_object?
        @name_or_object
      else
        strategy_name_to_object
      end
    end

    private

    def strategy_is_object?
      @name_or_object.is_a?(Class)
    end

    def strategy_name_to_object
      FactoryBot.strategy_by_name(@name_or_object)
    end
  end
end
