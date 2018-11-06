#
# Gems
#
# gems must load explicitly any gem declared in gemspec
# @see https://github.com/bundler/bundler/issues/2018#issuecomment-6819359
#
#

require 'active_model'
require 'active_support'

autoload :IpFormatValidator, 'ip_format_validator'
autoload :NilValidator, 'nil_validator'
autoload :ParametersValidator, 'parameters_validator'
autoload :PasswordIsStrongValidator, 'password_is_strong_validator'

# Top-level namespace shared between metasploit-model, metasploit-framework, and Pro.
module Metasploit
  # The namespace for this gem.  All code under the {Metasploit::Model} namespace is code that is shared between
  # in-memory ActiveModels in metasploit-framework and database ActiveRecords in metasploit_data_models.  Having a
  # separate gem for this shard code outside of metasploit_data_models is necessary as metasploit_data_models is an
  # optional dependency for metasploit-framework as metasploit-framework can work without a database.
  module Model
    extend ActiveSupport::Autoload

    autoload :Architecture
    autoload :Association
    autoload :Author
    autoload :Authority
    autoload :Base
    autoload :Derivation
    autoload :EmailAddress
    autoload :Error
    autoload :File
    autoload :Invalid
    autoload :Login
    autoload :Module
    autoload :NilifyBlanks
    autoload :Platform
    autoload :RealPathname
    autoload :Realm
    autoload :Reference
    autoload :Search
    autoload :Spec
    autoload :Translation
    autoload :Visitation
  end
end

#
# Project - require Metasploit::Model to be defined
#

# MUST require and not autoload as Rails::Engine loading works based subclass registration
require 'metasploit/model/version'
