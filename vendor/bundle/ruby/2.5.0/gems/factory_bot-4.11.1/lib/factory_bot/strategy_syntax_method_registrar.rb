module FactoryBot
  # @api private
  class StrategySyntaxMethodRegistrar
    def initialize(strategy_name)
      @strategy_name = strategy_name
    end

    def define_strategy_methods
      define_singular_strategy_method
      define_list_strategy_method
      define_pair_strategy_method
    end

    private

    def define_singular_strategy_method
      strategy_name = @strategy_name

      define_syntax_method(strategy_name) do |name, *traits_and_overrides, &block|
        FactoryRunner.new(name, strategy_name, traits_and_overrides).run(&block)
      end
    end

    def define_list_strategy_method
      strategy_name = @strategy_name

      define_syntax_method("#{strategy_name}_list") do |name, amount, *traits_and_overrides, &block|
        unless amount.respond_to?(:times)
          raise ArgumentError, "count missing for #{strategy_name}_list"
        end

        amount.times.map { send(strategy_name, name, *traits_and_overrides, &block) }
      end
    end

    def define_pair_strategy_method
      strategy_name = @strategy_name

      define_syntax_method("#{strategy_name}_pair") do |name, *traits_and_overrides, &block|
        2.times.map { send(strategy_name, name, *traits_and_overrides, &block) }
      end
    end

    def define_syntax_method(name, &block)
      FactoryBot::Syntax::Methods.module_exec do
        if method_defined?(name) || private_method_defined?(name)
          undef_method(name)
        end

        define_method(name, &block)
      end
    end
  end
end
