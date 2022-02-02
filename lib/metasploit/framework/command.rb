#
# Gems
#

# have to be exact so minimum is loaded prior to parsing arguments which could
# influence loading.
require 'active_support/dependencies/autoload'

# @note Must use the nested declaration of the
# {Metasploit::Framework::Command} namespace because commands need to be able
# to be required directly without any other part of metasploit-framework
# besides config/boot so that the commands can parse arguments, setup
# RAILS_ENV, and load config/application.rb correctly.
module Metasploit
  module Framework
    module Command
      # Namespace for commands for metasploit-framework.  There are
      # corresponding classes in the {Metasploit::Framework::ParsedOptions}
      # namespace, which handle for parsing the options for each command.
      extend ActiveSupport::Autoload

      autoload :Base
      autoload :Console
    end
  end
end
