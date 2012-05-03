# encoding: utf-8

module Formtastic
  # Copies formtastic.css to public/stylesheets/ (Rails 3.0.x only) and a config initializer
  # to config/initializers/formtastic.rb (all Rails versions).
  #
  # @example
  #   $ rails generate formtastic:install
  #
  # @todo Test with Rails 3.0
  class InstallGenerator < Rails::Generators::Base
    source_root File.expand_path('../../../templates', __FILE__)
    class_option :template_engine

    if ::Rails::VERSION::MAJOR == 3 && ::Rails::VERSION::MINOR >= 1
      # Rails 3.1 has the asset pipeline, no need to copy CSS files any more
      desc "Copies a config initializer to config/initializers/formtastic.rb"
      def copy_files
        copy_file 'formtastic.rb', 'config/initializers/formtastic.rb'
      end
    else
      # Rails 3.0 doesn't have an asset pipeline, so we copy in CSS too
      desc "Copies some CSS files to public/stylesheets/ and a config initializer to config/initializers/formtastic.rb"
      def copy_files
        template 'formtastic.rb', 'config/initializers/formtastic.rb'
        template '../../../app/assets/stylesheets/formtastic.css',     'public/stylesheets/formtastic.css'
        template '../../../app/assets/stylesheets/formtastic_ie6.css', 'public/stylesheets/formtastic_ie6.css'
        template '../../../app/assets/stylesheets/formtastic_ie7.css', 'public/stylesheets/formtastic_ie7.css'
      end
    end

    def copy_scaffold_template
      engine = options[:template_engine]
      copy_file "_form.html.#{engine}", "lib/templates/#{engine}/scaffold/_form.html.#{engine}"
    end
  end
end
