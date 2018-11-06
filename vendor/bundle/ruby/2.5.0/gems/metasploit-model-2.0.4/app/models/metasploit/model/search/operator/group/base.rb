# Operator that {#operate_on produces} {Metasploit::Model::Search::Operation::Group::Base group operations}.
class Metasploit::Model::Search::Operator::Group::Base < Metasploit::Model::Search::Operator::Delegation
  #
  # Class Attributes
  #

  # @!method self.operation_class_name()
  #   The name of the {operation_class}.
  #
  #   @return [String]
  #
  # @!method self.operation_class_name=(operation_class_name)
  #   Set the name of the {operation_class}.
  #
  #   @param operation_class_name [String]
  #   @return [void]
  class_attribute :operation_class_name

  #
  # Class Methods
  #

  # {Metasploit::Model::Search::Operation::Group::Base Group operation class} to wrap {#children} in and return from
  # {#operate_on}.
  #
  # @return [Class<Metasploit::Model::Search::Operation::Group::Base>]
  def self.operation_class
    @operation_class ||= operation_class_name.constantize
  end

  # Sets the {operation_class_name} to the operation with same name as this operator, but with 'Operation' substituted
  # for 'Operator'.
  #
  # @return (see operation_class_name=)
  def self.operation_class_name!
    self.operation_class_name = name.gsub('Operator', 'Operation')
  end

  operation_class_name!

  #
  # Instance Methods
  #

  # {Metasploit::Model::Search::Operation::Group::Base#children}.
  #
  # @param formatted_value [String] value parsed from formatted operation
  # @return [Array<Metasploit::Model::Search::Operation::Base>]
  def children(formatted_value)
    raise NotImplementedError
  end

  # (see operation_class)
  def operation_class
    self.class.operation_class
  end

  # Group's children operating on `formatted_value`.
  #
  # @param formatted_value [String] value parsed from formatted operation.
  # @return [Metasploit::Model::Search::Operation::Group::Base] {#operation_class} instance will not contain {#children}
  #   that are invalid.
  def operate_on(formatted_value)
    children = self.children(formatted_value)

    # filter children for validity as valid values for one child won't necessarily be valid values for another child.
    # this is specifically a problem with Metasploit::Model::Search::Operation::Set as no partial matching is allowed,
    # but can also be a problem with string vs integer operations.
    valid_children = children.select(&:valid?)

    operation_class.new(
        :children => valid_children,
        :operator => self,
        :value => formatted_value
    )
  end
end