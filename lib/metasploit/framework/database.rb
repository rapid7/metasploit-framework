require 'metasploit/framework'

# Helpers for accessing the database configuration for running specs.
module Metasploit::Framework::Database
  # Loads YAML configuration from {configurations_pathname}.
  #
  # @return [Hash]
  def self.configurations
    erb_content = configurations_pathname.read
    erb = ERB.new(erb_content)
    yaml_content = erb.result
    YAML::load(yaml_content)
  end

  # Pathname to database.yml used for specs.
  #
  # @return [Pathname] config/database.yml
  def self.configurations_pathname
    Metasploit::Framework.root.join('config', 'database.yml')
  end
end
