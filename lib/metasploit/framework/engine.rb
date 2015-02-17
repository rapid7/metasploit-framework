#
# Gems
#

require 'rails/engine'

#
# Project
#

require 'metasploit/framework/common_engine'

module Metasploit
  module Framework
    class Engine < Rails::Engine
      include Metasploit::Framework::CommonEngine
    end
  end
end
