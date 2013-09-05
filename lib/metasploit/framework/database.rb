require 'metasploit/framework'

module Metasploit
  module Framework
    module Database
      def self.configurations
        YAML.load_file(configurations_pathname)
      end

      def self.configurations_pathname
        Metasploit::Framework.root.join('config', 'database.yml')
      end
    end
  end
end
