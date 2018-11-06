
#
# Gems
#
# gems must load explicitly any gem declared in gemspec
# @see https://github.com/bundler/bundler/issues/2018#issuecomment-6819359
#
#

require 'metasploit/concern'
require 'metasploit_data_models'
require 'metasploit/model'
require 'zip'

#
# Project
#

autoload :NonNilValidator, 'non_nil_validator'

# Shared namespace for metasploit gems; used in {https://github.com/rapid7/metasploit-credential metasploit-credential},
# {https://github.com/rapid7/metasploit-framework metasploit-framework}, and
# {https://github.com/rapid7/metasploit-model metasploit-model}
module Metasploit
  # The namespace for this gem.
  module Credential
    extend ActiveSupport::Autoload

    autoload :BlankPassword
    autoload :BlankUsername
    autoload :Core
    autoload :CoreValidations
    autoload :Creation
    autoload :Engine
    autoload :EntityRelationshipDiagram
    autoload :Exporter
    autoload :Importer
    autoload :Login
    autoload :Migrator
    autoload :NonreplayableHash
    autoload :NTLMHash
    autoload :Origin
    autoload :Password
    autoload :PasswordHash
    autoload :PostgresMD5
    autoload :Private
    autoload :Public
    autoload :Realm
    autoload :ReplayableHash
    autoload :Search
    autoload :SSHKey
    autoload :Text
    autoload :Username

    # The prefix for all `ActiveRecord::Base#table_name`s for `ActiveRecord::Base` subclasses under this namespace.
    #
    # @return [String] `'metasploit_credential_'`
    def self.table_name_prefix
      'metasploit_credential_'
    end
  end
end

