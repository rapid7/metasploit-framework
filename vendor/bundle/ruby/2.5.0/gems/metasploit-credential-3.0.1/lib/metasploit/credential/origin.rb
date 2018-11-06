# Namespace for `Metasploit::Credential::Core#origin`s for `Metasploit::Credential::Core`s.
module Metasploit::Credential::Origin
  extend ActiveSupport::Autoload

  autoload :CrackedPassword
  autoload :Import
  autoload :Manual
  autoload :Service
  autoload :Session

  # The prefix for table name of `ActiveRecord::Base` subclasses in the namespace.
  #
  # @return [String] `'metasploit_credential_origin_'`
  def self.table_name_prefix
    'metasploit_credential_origin_'
  end
end
