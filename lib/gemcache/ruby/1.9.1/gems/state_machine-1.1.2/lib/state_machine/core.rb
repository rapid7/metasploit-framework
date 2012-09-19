# Load all of the core implementation required to use state_machine.  This
# includes:
# * StateMachine::MacroMethods which adds the state_machine DSL to your class
# * A set of initializers for setting state_machine defaults based on the current
#   running environment (such as within Rails)
require 'state_machine/macro_methods'
require 'state_machine/initializers'
