require 'rspec/core'
require 'rails/version'

# Load any of our adapters and extensions early in the process
require 'rspec/rails/adapters'
require 'rspec/rails/extensions'

# Load the rspec-rails parts
require 'rspec/rails/view_rendering'
require 'rspec/rails/matchers'
require 'rspec/rails/fixture_support'
require 'rspec/rails/file_fixture_support'
require 'rspec/rails/fixture_file_upload_support'
require 'rspec/rails/example'
require 'rspec/rails/vendor/capybara'
require 'rspec/rails/configuration'
require 'rspec/rails/active_record'
require 'rspec/rails/feature_check'
