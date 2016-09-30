#
# Gems
#

require 'active_support/dependencies/autoload'

# @note Must use the nested declaration of the
#   {Metasploit::Framework::ParsedOptions} namespace because commands, which
#   use parsed options, need to be able to be required directly without any
#   other part of metasploit-framework besides config/boot so that the
#   commands can parse arguments, setup RAILS_ENV, and load
#   config/application.rb correctly.
module Metasploit
  module Framework
    # Namespace for parsed options for {Metasploit::Framework::Command
    # commands}.  The names of `Class`es in this namespace correspond to the
    # name of the `Class` in the {Metasploit::Framework::Command} namespace
    # for which this namespace's `Class` parses options.
    module ParsedOptions
      extend ActiveSupport::Autoload

      autoload :Base
      autoload :Console
    end
  end
end

