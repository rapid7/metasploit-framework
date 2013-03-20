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

    initializer 'metasploit_data_models.prepend_factory_path', :after => 'factory_girl.set_factory_paths' do
      if defined? FactoryGirl
        relative_definition_file_path = config.generators.options[:factory_girl][:dir]
        definition_file_path = root.join(relative_definition_file_path)

        # unshift so that Pro can modify mdm factories
        FactoryGirl.definition_file_paths.unshift definition_file_path
      end
    end
  end
end
