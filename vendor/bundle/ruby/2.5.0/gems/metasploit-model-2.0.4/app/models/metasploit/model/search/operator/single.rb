# If all you want do is customize the name and operation `Class` that your custom operator class returns from
# `#operate_on`, then you can subclass {Metasploit::Model::Search::Operator::Single} instead of
# {Metasploit::Model::Search::Operator::Base}.
#
#     class MyOperator < Metasploit::Model::Search::Operator::Single
#       # Name of this operator.  The name of the operator is matched to the string before the ':' in a formatted
#       # operation.
#       #
#       # @return [Symbol]
#       def name
#         # ...
#       end
#
#       # `Class.name` of `Class` returned from {Metasploit::Model::Search::Operator::Single#operate_on}.
#       #
#       # @return [String] a `Class.name`
#       def operation_class_name
#         # ...
#       end
#     end
#
class Metasploit::Model::Search::Operator::Single < Metasploit::Model::Search::Operator::Base
  #
  # CONSTANTS
  #

  # Separator between parent and child module/class names.
  MODULE_SEPARATOR = '::'
  # Name of namespace module for operations returned from {#operation_class} and used by {#operate_on}.
  OPERATION_NAMESPACE_NAME = "Metasploit::Model::Search::Operation"

  #
  # Methods
  #

  # The constant name for the given type.
  #
  # @param type [Symbol, Hash]
  # @return [String]
  def self.constant_name(type)
    case type
      when Hash
        if type.length < 1
          raise ArgumentError, "Cannot destructure a Hash without entries"
        end

        if type.length > 1
          raise ArgumentError, "Cannot destructure a Hash with multiple entries"
        end

        partial_types = type.first
        partial_constant_names = partial_types.collect { |partial_type|
          constant_name(partial_type)
        }

        partial_constant_names.join(MODULE_SEPARATOR)
      when Symbol
        type.to_s.camelize
      else
        raise ArgumentError, "Can only convert Hashes and Symbols to constant names, not #{type.inspect}"
    end
  end

  # Creates an {Metasploit::Model::Search::Operation::Base operation} of the correct type for this operator's {#type}.
  #
  # @param formatted_value [String] the unparsed value passed to this operator in {Metasploit::Model::Search::Query
  #   a formatted search query}.
  # @return [Metasploit::Model::Search::Operation::Base] instance of {#operation_class}.
  def operate_on(formatted_value)
    operation_class.new(
        :value => formatted_value,
        :operator => self
    )
  end

  # @abstract subclass and derive operator type.
  #
  # Type of the attribute.
  #
  # @return [Symbol]
  # @raise [NotImplementedError]
  def type
    raise NotImplementedError
  end

  protected

  # The {#type}-specific {Metasploit::Model::Search::Operation::Base} subclass.
  #
  # @return [Class<Metasploit::Model::Search::Operation::Base>]
  # @raise (see #operation_class_name)
  def operation_class
    unless instance_variable_defined? :@operation_class
      @operation_class = operation_class_name.constantize
    end

    @operation_class
  end

  # The name of the {#type}-specific {Metasploit::Model::Search::Operation::Base} subclass.
  #
  # @return [String]
  # @raise [ArgumentError]
  def operation_class_name
    unless instance_variable_defined? :@operation_class_name
      unless type
        raise ArgumentError, "#{self.class}##{__method__} cannot be derived for #{name} operator because its type is nil"
      end

      partial_constant_names = [OPERATION_NAMESPACE_NAME]
      partial_constant_names << self.class.constant_name(type)

      @operation_class_name = partial_constant_names.join(MODULE_SEPARATOR)
    end

    @operation_class_name
  end
end