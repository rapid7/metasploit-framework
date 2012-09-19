# By default, requiring "state_machine" means that both the core implementation
# *and* extensions to the Ruby core (Class in particular) will be pulled in.
# 
# If you want to skip the Ruby core extensions, simply require "state_machine/core"
# and extend StateMachine::MacroMethods in your class.  See the README for more
# information.
require 'state_machine/core'
require 'state_machine/core_ext'
