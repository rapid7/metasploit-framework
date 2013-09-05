require 'metasploit/framework'

# Helpers for accessing the database configuration for running specs.
module Metasploit::Framework::Database
  # Loads YAML configuration from {configurations_pathname}.
  #
  # @return [Hash]
  def self.configurations
    YAML.load_file(configurations_pathname)
  end

  # Pathname to database.yml used for specs.
  #
  # @return [Pathname] config/database.yml
  def self.configurations_pathname
    Metasploit::Framework.root.join('config', 'database.yml')
  end
end
