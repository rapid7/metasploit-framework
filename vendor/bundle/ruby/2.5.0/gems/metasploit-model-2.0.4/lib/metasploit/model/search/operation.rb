# Namespace for search operations.  {parse} acts as a factory to parse a `String` and return a type-specific
# operation.
module Metasploit::Model::Search::Operation
  extend ActiveSupport::Autoload

  autoload :Association
  autoload :Base
  autoload :Boolean
  autoload :Date
  autoload :Group
  autoload :Integer
  autoload :Null
  autoload :Set
  autoload :String
  autoload :Value

  # @param options [Hash{Symbol => Object}]
  # @option options [Metasploit::Module::Search::Query] :query The query that the parsed operation is a part.
  # @option options [String] :formatted_operation A '<operator>:<value>' string.
  # @return [Metasploit::Model::Search::Operation::Base, Array<Metasploit::Model::Search::Operation::Base>]
  #   operation(s) parsed from the formatted operation.
  # @raise [KeyError] unless :formatted_operation is given.
  # @raise [KeyError] unless :query is given.
  def self.parse(options={})
    formatted_operation = options.fetch(:formatted_operation)
    query = options.fetch(:query)

    formatted_operator, formatted_value = formatted_operation.split(':', 2)
    operator = query.parse_operator(formatted_operator)

    # formatted_value will be nil if formatted_operation did not contain a ':', it should be treated the same
    # as nothing after the ':'.
    formatted_value ||= ''
    operation_or_operations = operator.operate_on(formatted_value)

    operation_or_operations
  end
end
