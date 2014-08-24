require 'metasploit/framework'

module Metasploit
  module Framework
    module Database
      def self.configurations
        YAML.load_file(configurations_pathname)
      end

      def self.configurations_pathname
        Metasploit::Framework::Application.paths['config/database'].first
      end
    end
  end
end
