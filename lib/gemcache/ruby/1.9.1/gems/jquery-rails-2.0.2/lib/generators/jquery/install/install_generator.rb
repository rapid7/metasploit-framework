require 'rails'

# Supply generator for Rails 3.0.x or if asset pipeline is not enabled
if ::Rails.version < "3.1" || !::Rails.application.config.assets.enabled
  module Jquery
    module Generators
      class InstallGenerator < ::Rails::Generators::Base

        desc "This generator installs jQuery #{Jquery::Rails::JQUERY_VERSION}, jQuery-ujs, and (optionally) jQuery UI #{Jquery::Rails::JQUERY_UI_VERSION}"
        class_option :ui, :type => :boolean, :default => false, :desc => "Include jQueryUI"
        source_root File.expand_path('../../../../../vendor/assets/javascripts', __FILE__)

        def remove_prototype
          Rails::PROTOTYPE_JS.each do |name|
            remove_file "public/javascripts/#{name}.js"
          end
        end

        def copy_jquery
          say_status("copying", "jQuery (#{Jquery::Rails::JQUERY_VERSION})", :green)
          copy_file "jquery.js", "public/javascripts/jquery.js"
          copy_file "jquery.min.js", "public/javascripts/jquery.min.js"
        end

        def copy_jquery_ui
          if options.ui?
            say_status("copying", "jQuery UI (#{Jquery::Rails::JQUERY_UI_VERSION})", :green)
            copy_file "jquery-ui.js", "public/javascripts/jquery-ui.js"
            copy_file "jquery-ui.min.js", "public/javascripts/jquery-ui.min.js"
          end
        end

        def copy_ujs_driver
          say_status("copying", "jQuery UJS adapter (#{Jquery::Rails::JQUERY_UJS_VERSION[0..5]})", :green)
          remove_file "public/javascripts/rails.js"
          copy_file "jquery_ujs.js", "public/javascripts/jquery_ujs.js"
        end

      end
    end
  end
else
  module Jquery
    module Generators
      class InstallGenerator < ::Rails::Generators::Base
        desc "Just show instructions so people will know what to do when mistakenly using generator for Rails 3.1 apps"

        def do_nothing
          say_status("deprecated", "You are using Rails 3.1 with the asset pipeline enabled, so this generator is not needed.")
          say_status("", "The necessary files are already in your asset pipeline.")
          say_status("", "Just add `//= require jquery` and `//= require jquery_ujs` to your app/assets/javascripts/application.js")
          say_status("", "If you upgraded your app from Rails 3.0 and still have jquery.js, rails.js, or jquery_ujs.js in your javascripts, be sure to remove them.")
          say_status("", "If you do not want the asset pipeline enabled, you may turn it off in application.rb and re-run this generator.")
          # ok, nothing
        end
      end
    end
  end
end
