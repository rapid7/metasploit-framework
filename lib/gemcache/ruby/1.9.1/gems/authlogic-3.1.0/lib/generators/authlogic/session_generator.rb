module Authlogic
  class SessionGenerator < Rails::Generators::Base
    source_root File.expand_path('../templates', __FILE__)
    argument :session_class_name, :type => :string, :default => "Session"

    def self.banner
      "rails generate authlogic:#{generator_name} #{self.arguments.map{ |a| a.usage }.join(' ')} [options]"
    end
  
    def generate_session
      template "session.rb", "app/models/#{session_class_name.underscore}.rb"
    end
  end
end
