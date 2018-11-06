module FactoryBotRails
  module Generators
    class RSpecGenerator
      def initialize(generators)
        @generators = generators
      end

      def run
        @generators.fixture_replacement fixture_replacement_setting, dir: factory_bot_directory
      end

      private

      def fixture_replacement_setting
        @generators.options[:rails][:fixture_replacement] || :factory_bot
      end

      def factory_bot_directory
        @generators.options.fetch(:factory_bot, {}).fetch(:dir, 'spec/factories')
      end
    end
  end
end
