# Validates that attribute's value is Array<Array(String, String)> which is the only valid type signature for serialized
# parameters.
class ParametersValidator < ActiveModel::EachValidator
  # Sentence explaining the valid type signature for parameters.
  TYPE_SIGNATURE_SENTENCE = 'Valid parameters are an Array<Array(String, String)>.'

  # Validates that attribute's value is Array<Array(String, String)> which is the only valid type signature for
  # serialized parameters.  Errors are specific to the how different `value` is compared to correct format.
  #
  # @param record [#errors, ActiveRecord::Base] ActiveModel or ActiveRecord
  # @param attribute [Symbol] serialized parameters attribute name.
  # @param value [Object, nil, Array, Array<Array>, Array<Array(String, String)>] serialized parameters.
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

  # Generates error message for element at the given index.  Prefix is prepened to {#location_clause} to make a
  # sentence.  {TYPE_SIGNATURE_SENTENCE} is appended to that sentence.
  #
  # @param options [Hash{Symbol => Object}]
  # @option options [Object] :element The element that has the error.
  # @option options [Integer] :index The index of element in its parent Array.
  # @option options [String] :prefix Specific error prefix to differentiate from other calls to {#error_at}.
  # @return [String]
  # @see #location_clause
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

  # Generates error message for too few or too many elements.
  #
  # @param options [Hash{Symbol => Object}]
  # @option options [Array] :element Array that has the wrong number of elements.
  # @option options [:few, :many] :extreme whether :element has too `:few` or too `:many` child elements.
  # @option options [Integer] :index index of `:element` in its parent Array.
  # @return [String]
  # @see {#error_at}
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

  # Generates a clause with the location of element and its value.
  #
  # @param options [Hash{Symbol => String,Integer}]
  # @option options [Object, #inspect] :element an element in a parent Array.
  # @option options [Integer] :index index of `:element` in parent Array.
  # @return [String] "at index <index> (<element.inspect>)"
  def location_clause(options={})
    options.assert_valid_keys(:element, :index)

    element = options.fetch(:element)
    index = options.fetch(:index)

    clause = "at index #{index} (#{element.inspect})"

    clause
  end
end