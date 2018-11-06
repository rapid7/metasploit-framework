require 'factory_bot_rails/generators/rspec_generator'
require 'factory_bot_rails/generators/non_rspec_generator'
require 'factory_bot_rails/generators/null_generator'

module FactoryBotRails
  class Generator
    def initialize(config)
      @generators = if config.respond_to?(:app_generators)
                      config.app_generators
                    else
                      config.generators
                    end
    end

    def run
      generator.new(@generators).run
    end

    def generator
      if factory_bot_disabled?
        Generators::NullGenerator
      else
        if test_framework == :rspec
          Generators::RSpecGenerator
        else
          Generators::NonRSpecGenerator
        end
      end
    end

    def test_framework
      rails_options[:test_framework]
    end

    def factory_bot_disabled?
      rails_options[:factory_bot] == false
    end

    def rails_options
      @generators.options[:rails]
    end
  end
end
