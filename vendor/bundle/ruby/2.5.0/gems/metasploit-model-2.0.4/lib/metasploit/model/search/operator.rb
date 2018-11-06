# # Declaring operator classes
#
# ## Interface
#
# Operators do not need to subclass any specific superclass, but they are expected to define certain methods.
#
#     class MyOperator
#       #
#       # Instance Methods
#       #
#
#       # @param klass [Class] The klass on which `search_with` was called.
#       def initialize(attributes={})
#         # ...
#       end
#
#       # Description of what this operator searches for.
#       #
#       # @return [String]
#       def help
#         # ...
#       end
#
#       # Name of this operator.  The name of the operator is matched to the string before the ':' in a formatted
#       # operation.
#       #
#       # @return [Symbol]
#       def name
#         # ...
#       end
#
#       # Creates a one or more operations based on `formatted_value`.
#       #
#       # @return [#operator, Array<#operator>] Operation with this operator as the operation's `operator`.
#       def operate_on(formatted_value)
#         # ...
#       end
#     end
#
# ## Help
#
# Instead of having define your own `#help` method for your operator `Class`, you can `include`
# {Metasploit::Model::Search::Operator::Help}.
#
# {include:Metasploit::Model::Search::Operator::Help}
#
# ## {Metasploit::Model::Search::Operator::Base}
#
# {include:Metasploit::Model::Search::Operator::Base}
#
# ## {Metasploit::Model::Search::Operator::Single}
#
# {include:Metasploit::Model::Search::Operator::Single}
module Metasploit::Model::Search::Operator
  extend ActiveSupport::Autoload

  autoload :Association
  autoload :Attribute
  autoload :Base
  autoload :Delegation
  autoload :Deprecated
  autoload :Group
  autoload :Help
  autoload :Null
  autoload :Single
end
