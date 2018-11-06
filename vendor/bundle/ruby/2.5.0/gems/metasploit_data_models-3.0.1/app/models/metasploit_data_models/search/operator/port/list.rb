# Searches for a network port attribute.  Ports can be given as a single number or range of numbers and either or both
# forms can be combined into a comma separated list.  Individual port numbers are validated to be greater than 0 and
class MetasploitDataModels::Search::Operator::Port::List < Metasploit::Model::Search::Operator::Group::Union
  #
  # CONSTANTS
  #

  # Separates port number and/or port ranges
  SEPARATOR = ','

  #
  # Attributes
  #

  # @!attribute [rw] attribute
  #   Attribute holding port number.
  #
  #   @return [Symbol] `:port`
  attr_writer :attribute

  #
  # Class Methods
  #

  # @note Can't be called `name` because it would alias `Class#name`
  #
  # Name of this operator.
  #
  # @return [String] `'port_list'`
  def self.operator_name
    'port_list'
  end

  #
  # Instance Methods
  #

  # Defaults to `:port`.
  #
  # @return [Symbol]
  def attribute
    @attribute ||= :port
  end

  # Turns `{#attribute}:<number>,<range>` into the union of port <number> and port <range> searches.
  #
  # @param formatted_value [String] comma separated list of port numbers and ranges.
  # @return [Array<Metasploit::Model::Search::Operation::Base]
  def children(formatted_value)
    separated_formatted_values = formatted_value.split(SEPARATOR)

    separated_formatted_values.collect { |separated_formatted_value|
      operation_class = MetasploitDataModels::Search::Operation::Port::Number

      if separated_formatted_value.include? MetasploitDataModels::Search::Operation::Range::SEPARATOR
        operation_class = MetasploitDataModels::Search::Operation::Port::Range
      end

      operation_class.new(
          value: separated_formatted_value,
          operator: self
      )
    }
  end

  alias_method :name, :attribute
end
