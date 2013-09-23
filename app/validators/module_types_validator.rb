require 'set'

# Validator for a collection that holds a subset of `Metasploit::Model::Module::Type::ALL`.
class ModuleTypesValidator < ActiveModel::EachValidator
  #
  # CONSTANTS
  #

  # All module types in human set notation.
  FORMATTED_MODULE_TYPES= "{#{Metasploit::Model::Module::Type::ALL.join(', ')}}"
  # Set of all module types.
  MODULE_TYPE_SET = Metasploit::Model::Module::Type::ALL.to_set

  #
  # Methods
  #

  # Validates that `attribute`'s `value` is a subset of `Metasploit::Model::Module::Type::ALL` with at least one item.
  #
  # @param record [#errors, ActiveRecord::Base] ActiveModel or ActiveRecord
  # @param attribute [Symbol] name attribute holding module types.
  # @param value [Array<String>, nil] value of `attribute` in `record`.
  # @return [void]
  def validate_each(record, attribute, value)
    if value.blank?
      record.errors.add(attribute, :blank)
    else
      begin
        value_set = Set.new(value)
      rescue ArgumentError
        # value is not enumerable, such as when the user supplies a String instead of Array<String>.
        record.errors.add(
            attribute,
            :invalid_module_types,
            valid_module_types: FORMATTED_MODULE_TYPES
        )
      else
        invalid_module_types = value_set - MODULE_TYPE_SET

        invalid_module_types.each do |invalid_module_type|
          record.errors.add(
              attribute,
              :invalid_module_type,
              invalid_module_type: invalid_module_type,
              valid_module_types: FORMATTED_MODULE_TYPES
          )
        end
      end
    end
  end
end