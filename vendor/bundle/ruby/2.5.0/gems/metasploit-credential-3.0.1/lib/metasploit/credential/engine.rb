require 'rails'

# Rails engine for Metasploit::Credential.
class Metasploit::Credential::Engine < Rails::Engine
  # @see http://viget.com/extend/rails-engine-testing-with-rspec-capybara-and-factorygirl
  config.generators do |g|
    g.assets false
    g.fixture_replacement :factory_girl, dir: 'spec/factories'
    g.helper false
    g.test_framework :rspec, fixture: false
  end

  # Remove ActiveSupport::Dependencies loading paths to save time during constant resolution and to ensure that
  # metasploit_data_models is properly declaring all autoloads and not falling back on ActiveSupport::Dependencies
  config.paths.values.each do |path|
    path.skip_autoload!
    path.skip_autoload_once!
    path.skip_eager_load!
    path.skip_load_path!
  end

  # metasploit-concern only works with ActiveSupport::Dependencies.autoloading because the extended class only
  # knows about the concerns from the load hooks and so the extended class can't use Kernel.autoload to load the
  # concerns.
  config.paths.add 'app/concerns', autoload: true

  initializer 'metasploit_credential.prepend_factory_path',
              # factory paths from the final Rails.application
              after: 'factory_girl.set_factory_paths',
              # before metasploit_data_models because it prepends
              before: 'metasploit_data_models.prepend_factory_path' do
    if defined? FactoryBot
      relative_definition_file_path = config.generators.options[:factory_girl][:dir]
      definition_file_path = root.join(relative_definition_file_path)

      # unshift so that projects that use metasploit-credential can modify metasploit_credential_* factories
      FactoryBot.definition_file_paths.unshift definition_file_path
    end
  end
end
