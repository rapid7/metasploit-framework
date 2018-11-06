require 'rspec/core/shared_example_group'

# Helper methods for running specs for metasploit-model.
module Metasploit::Model::Spec
  extend ActiveSupport::Autoload

  autoload :Error
  autoload :I18nExceptionHandler
  autoload :PathnameCollision
  autoload :Template
  autoload :TemporaryPathname

  extend Metasploit::Model::Spec::TemporaryPathname
end
