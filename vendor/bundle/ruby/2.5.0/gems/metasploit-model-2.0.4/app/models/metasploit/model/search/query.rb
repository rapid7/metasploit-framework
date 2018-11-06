# Once {Metasploit::Model::Search::Operator search operators} are {Metasploit::Model::Search defined}, a formatted
# query, composed of space separated formatted operation, `<operator.name>:<formatted_value>`, can be parsed to
# produce a validatable query.
#
#     query = Metasploit::Model::Search::Query.new(
#       formatted: 'parts.number:1 parts.number:2 parts.uuid:EX,QR'
#     )
#
# Operations using the same operator are unioned together, while operations with different operator are intersected
# together, so the above formatted query can be thought of as
# `(parts.number:1 || parts.number:2) && parts.uuid:EX,QR`.
#
# # Results
#
# Once a {Metasploit::Model::Search::Query} is defined, it needs to be converted to a data store specific visitor.
#
# Visitors for `ActiveRecord` are defined in
# {http://rubydoc.info/gems/metasploit_data_models/MetasploitDataModels/Search/Visitor MetasploitDataModels::Search::Visitor}.
#
# If you want to define your own visitors, you can subclass {Metasploit::Model::Visitation::Visitor}.
class Metasploit::Model::Search::Query < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] formatted
  #   Query string containing space separated <operator>:<value> pairs.
  #
  #   @return [String]
  attr_accessor :formatted

  # @!attribute [rw] formatted_operations
  #   @note If using `Shellwords.shellsplit` to pre-parse the query, set {#formatted_operations} instead of rejoining
  #     the shell words with `.join(" ")` and setting {#formatted} as `Shellwords.shellsplit` strips embedded quotes,
  #     so quoted spaces will not be handled correctly if joining and setting {#formatted}.
  #
  #   {#formatted} broken up into individual operation (<operator>:<value>) Strings.
  attr_writer :formatted_operations

  # @!attribute [rw] klass
  #   The klass that is being searched.
  #
  #   @return [Class, #search_operator_by_name]
  attr_accessor :klass

  # @!attribute [rw] operations
  #   The parsed operations in this query.
  #
  #   @return [Array<Metasploit::Model::Search::Operation::Base>] An Array of operations.
  attr_writer :operations

  #
  # Validations
  #

  validates :klass, :presence => true

  validates :operations,
            :length => {
                :minimum => 1
            }
  # validate recursive so misnamed operators or bad values for operator's types cause the query to be invalid as a whole
  validate :operations_valid

  #
  # Methods
  #

  # Parses {#formatted} into a list of formatted operation composed of <formatted_operator>:<formatted_value> Strings.
  # <formatted_value> may be quoted
  #
  # @param formatted [String] a String composed of space-separated <formatted_operator>:<formatted_value>
  #   operations.  <formatted_value> may be quoted using the shell quoting rules.
  # @return [Array<String>] Array of formatted operation.
  # @see Shellwords.shellsplit
  def self.formatted_operations(formatted)
    Shellwords.shellsplit(formatted.to_s)
  end

  # {#formatted} broken up into individual operation (<operator>:<value>) Strings.
  #
  # @return [Array<String>]
  def formatted_operations
    @formatted_operations ||= self.class.formatted_operations(formatted)
  end

  # Parses {#formatted} to create search operations that can validate if the
  # {Metasploit::Model::Search::Operation::Base#value value} is correct the operation's
  # {Metasploit::Model::Search::Operation::Base#operator operator's} type.
  #
  # @return [Array<Metasploit::Model::Search::Operation::Base>] an Array of operation parsed from {#formatted}.
  def operations
    unless instance_variable_defined? :@operations
      @operations = formatted_operations.flat_map { |formatted_operation|
        Metasploit::Model::Search::Operation.parse(
            :formatted_operation => formatted_operation,
            :query => self
        )
      }
    end

    @operations
  end

  # @note Query is validated before grouping the operations as {Metasploit::Model::Search::Operation::Null operation
  # using unknown operators} with the same name should not be grouped together when processing this query into an actual
  # search of record and/or models.
  #
  # Groups {#operations} together by {Metasploit::Model::Search::Operation::Base#operator}.
  #
  # @return [Hash{Metasploit::Model::Search::Operator::Base => Metasploit::Model::Search::Operation::Base}] Maps
  #   operator to all its operations.
  # @raise [Metasploit::Model::Invalid] if query is invalid due to invalid operations.
  def operations_by_operator
    unless instance_variable_defined? :@operations_by_operator
      valid!

      @operations_by_operator = operations.group_by(&:operator)
    end

    @operations_by_operator ||= operations.group_by(&:operator)
  end

  # Converts formatted operator extracted from formatted operation to its {Metasploit::Model::Search::Operator::Base}
  # instance.
  #
  # @param formatted_operator [#to_sym] formatted operator as parsed from formatted operation.
  # @return [Metasploit::Model::Search::Operation::Base] a type-specific search operation if there is an
  #   {Metasploit::Model::Search::Operator::Base#name} on {#klass} that matches `formatted_operator`.
  # @return [Metasploit::Model::Search::Operator::Null] if there is not an operator with
  #   {Metasploit::Model::Search::Operator::Base#name} on {#klass} that matches `formatted_operator`.
  def parse_operator(formatted_operator)
    operator_name = formatted_operator.to_sym
    operator = klass.search_operator_by_name[operator_name]

    unless operator
      operator = Metasploit::Model::Search::Operator::Null.new(:name => operator_name)
    end

    operator
  end

  # Groups {#operations} together by {Metasploit::Model::Search::Operation::Base#operator} into
  # {Metasploit::Model::Search::Group::Union unions} that are
  # {Metasploit::Model::Search::Group::Intersection intersected}.
  #
  # @return [Metasploit::Model::Search::Group::Intersection<Metasploit::Model::Search::Group::Union<Metasploit::Model::Search::Operation::Base>>]
  def tree
    unless instance_variable_defined? :@tree
      unions = operations_by_operator.collect do |_operator, operations|
        Metasploit::Model::Search::Group::Union.new(:children => operations)
      end

      @tree = Metasploit::Model::Search::Group::Intersection.new(:children => unions)
    end

    @tree
  end

  # Returns a new query with all {#operations} on the given `operator` removed.
  #
  # @param operator [Metasploit::Model::Search::Operator::Base] an operator that should be removed from this query.
  # @return [Metasploit::Model:Search::Query] a new query if `operator` is a key in {#operations_by_operator}; otherwise
  #   this query.
  def without_operator(operator)
    operations = operations_by_operator[operator]

    if operations
      filtered_operations = self.operations - operations

      self.class.new(
          klass: klass,
          operations: filtered_operations
      )
    else
      self
    end
  end

  private

  # Validates that all {#operations} are valid.
  #
  # @return [void]
  def operations_valid
    unless operations.all?(&:valid?)
      errors.add(:operations, :invalid)
    end
  end
end