# Records the Bundler-style dependency constraint for the version of Rails to be
# used with the Metasploit Framework and Metasploit Pro.
module Metasploit
  module Framework
    module RailsVersionConstraint
      # Rails 8.0 upgrade: changed from '~> 7.2.0' to '~> 8.0.0'.
      # This constant is used in metasploit-framework.gemspec to pin activerecord,
      # activesupport, and actionpack. Rails 8.0 requires Rack 3.x and Zeitwerk-only
      # autoloading, which drove the broader upgrade across all supporting gems.
      RAILS_VERSION = '~> 8.0.0'
    end
  end
end
