# Records the Bundler-style dependency constraint for the version of Rails to be
# used with the Metasploit Framework and Metasploit Pro.
module Metasploit
  module Framework
    module RailsVersionConstraint

      # The Metasploit ecosystem is not yet ready for 2020:
      RAILS_VERSION = '~> 4.2.11'
    end
  end
end
