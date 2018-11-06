module FactoryBot
  module Syntax
    module Default
      include Methods

      def define(&block)
        DSL.run(block)
      end

      def modify(&block)
        ModifyDSL.run(block)
      end

      class DSL
        def factory(name, options = {}, &block)
          factory = Factory.new(name, options)
          proxy = FactoryBot::DefinitionProxy.new(factory.definition)
          proxy.instance_eval(&block) if block_given?

          FactoryBot.register_factory(factory)

          proxy.child_factories.each do |(child_name, child_options, child_block)|
            parent_factory = child_options.delete(:parent) || name
            factory(child_name, child_options.merge(parent: parent_factory), &child_block)
          end
        end

        def sequence(name, *args, &block)
          FactoryBot.register_sequence(Sequence.new(name, *args, &block))
        end

        def trait(name, &block)
          FactoryBot.register_trait(Trait.new(name, &block))
        end

        def to_create(&block)
          FactoryBot.to_create(&block)
        end

        def skip_create
          FactoryBot.skip_create
        end

        def initialize_with(&block)
          FactoryBot.initialize_with(&block)
        end

        def self.run(block)
          new.instance_eval(&block)
        end

        delegate :before, :after, :callback, to: :configuration

        private

        def configuration
          FactoryBot.configuration
        end
      end

      class ModifyDSL
        def factory(name, options = {}, &block)
          factory = FactoryBot.factory_by_name(name)
          proxy = FactoryBot::DefinitionProxy.new(factory.definition.overridable)
          proxy.instance_eval(&block)
        end

        def self.run(block)
          new.instance_eval(&block)
        end
      end
    end
  end

  extend Syntax::Default
end
