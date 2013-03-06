require 'rails'

module MetasploitDataModels
  class Engine < Rails::Engine

    # @see http://viget.com/extend/rails-engine-testing-with-rspec-capybara-and-factorygirl
    config.generators do |g|
      g.assets false
      g.fixture_replacement :factory_girl, :dir => 'spec/factories'
      g.helper false
      g.test_framework :rspec, :fixture => false
    end
  end
end