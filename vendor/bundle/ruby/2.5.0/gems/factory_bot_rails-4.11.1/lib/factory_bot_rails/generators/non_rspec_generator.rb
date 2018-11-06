module FactoryBotRails
  module Generators
    class NonRSpecGenerator
      def initialize(generators)
        @generators = generators
      end

      def run
        @generators.test_framework test_framework, fixture: false, fixture_replacement: :factory_bot
      end

      private

      def test_framework
        @generators.options[:rails][:test_framework]
      end
    end
  end
end
