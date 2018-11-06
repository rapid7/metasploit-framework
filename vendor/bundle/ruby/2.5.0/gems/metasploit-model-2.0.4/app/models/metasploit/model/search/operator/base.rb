# Instead of writing an operator completely from scratch, you can subclass
# {Metasploit::Model::Search::Operator::Base}.
#
#     class MyOperator < Metasploit::Model::Search::Operator::Base
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
class Metasploit::Model::Search::Operator::Base < Metasploit::Model::Base
  include ActiveModel::Validations
  include Metasploit::Model::Search::Operator::Help

  #
  # Attributes
  #

  # @!attribute [rw] klass
  #   The class on which this operator is usable.
  #
  #   @return [Class]
  attr_accessor :klass

  #
  # Validations
  #

  validates :klass, :presence => true

  # @abstract subclass and derive operator name from attributes of subclass.
  #
  # Name of this operator.
  #
  # @return [String]
  # @raise [NotImplementedError]
  def name
    raise NotImplementedError
  end
end