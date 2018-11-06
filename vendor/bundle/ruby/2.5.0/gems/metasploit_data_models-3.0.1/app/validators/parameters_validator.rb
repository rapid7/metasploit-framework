# Validates that attribute's value is Array<Array(String, String)> which is the only valid type signature for serialized
# parameters.
class ParametersValidator < ActiveModel::EachValidator
  #
  # CONSTANTS
  #

  # Sentence explaining the valid type signature for parameters.
  TYPE_SIGNATURE_SENTENCE = 'Valid parameters are an Array<Array(String, String)>.'

  #
  # Instance Methods
  #

  # Validates that `attribute`'s `value` on `record` is `Array<Array(String, String)>` which is the only valid type
  # signature for serialized parameters.
  #
  # @return [void]
  def validate_each(record, attribute, value)
    if value.is_a? Array
      value.each_with_index do |element, index|
        if element.is_a? Array
          if element.length != 2
            extreme = :few

            if element.length > 2
              extreme = :many
            end

            length_error = length_error_at(
                :extreme => extreme,
                :element => element,
                :index => index
            )

            record.errors[attribute] << length_error
          else
            parameter_name = element.first

            if parameter_name.is_a? String
              unless parameter_name.present?
                error = error_at(
                    :element => element,
                    :index => index,
                    :prefix => "has blank parameter name"
                )
                record.errors[attribute] << error
              end
            else
              error = error_at(
                  :element => element,
                  :index => index,
                  :prefix => "has non-String parameter name (#{parameter_name.inspect})"
              )
              record.errors[attribute] << error
            end

            parameter_value = element.second

            unless parameter_value.is_a? String
              error = error_at(
                  :element => element,
                  :index => index,
                  :prefix => "has non-String parameter value (#{parameter_value.inspect})"
              )
              record.errors[attribute] << error
            end
          end
        else
          error = error_at(
              :element => element,
              :index => index,
              :prefix => 'has non-Array'
          )
          record.errors[attribute] << error
        end
      end
    else
      record.errors[attribute] << "is not an Array.  #{TYPE_SIGNATURE_SENTENCE}"
    end
  end

  private

  def error_at(options={})
    options.assert_valid_keys(:element, :index, :prefix)
    prefix = options.fetch(:prefix)

    clause = location_clause(
        :element => options[:element],
        :index => options[:index]
    )
    sentence = "#{prefix} #{clause}."

    sentences = [
        sentence,
        TYPE_SIGNATURE_SENTENCE
    ]

    error = sentences.join("  ")

    error
  end

  def length_error_at(options={})
    options.assert_valid_keys(:element, :extreme, :index)
    extreme = options.fetch(:extreme)

    prefix = "has too #{extreme} elements"
    error = error_at(
        :element => options[:element],
        :index => options[:index],
        :prefix => prefix
    )

    error
  end

  def location_clause(options={})
    options.assert_valid_keys(:element, :index)

    element = options.fetch(:element)
    index = options.fetch(:index)

    clause = "at index #{index} (#{element.inspect})"

    clause
  end
end