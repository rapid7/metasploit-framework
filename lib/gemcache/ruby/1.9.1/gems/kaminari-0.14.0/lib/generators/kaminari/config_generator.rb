module Kaminari
  module Generators
    class ConfigGenerator < Rails::Generators::Base
      source_root File.expand_path(File.join(File.dirname(__FILE__), 'templates'))

      desc <<DESC
Description:
    Copies Kaminari configuration file to your application's initializer directory.
DESC

      def copy_config_file
        template 'kaminari_config.rb', 'config/initializers/kaminari_config.rb'
      end
    end
  end
end
