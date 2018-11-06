# Operation on an attribute that is a polymorphic type containing a `Class#name`.
class Metasploit::Credential::Search::Operation::Type < Metasploit::Model::Search::Operation::Base
  include ActiveModel::Validations::Callbacks

  #
  # Callbacks
  #

  before_validation :convert_value_to_class_name

  #
  # Validations
  #

  validate :class_name

  #
  # Instance Methods
  #

  private

  # Validates that {#formatted_value} either is a `Class.name` or is a `Class.model_name.human` that can be converted to
  # a `Class.name`.
  def class_name
    if operator && !operator.class_names.include?(value)
      human_class_name_conversions = operator.class_name_by_class_model_name_human.collect { |class_model_name_human, class_name|
        "#{class_model_name_human.inspect} => #{class_name.inspect}"
      }
      human_class_name_conversion = "{#{human_class_name_conversions.join(', ')}}"

      errors.add(
          :value,
          :class_name_conversion,
          class_name_conversion: human_class_name_conversion
      )
    end
  end

  # Converts the formatted value to a class name
  def convert_value_to_class_name
    if operator
      class_name = operator.class_name_by_class_model_name_human[@value]

      if class_name
        @value = class_name
      end
    end
  end
end