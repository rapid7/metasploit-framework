# -*- coding: binary -*-

module Msf
  module Ui
    module Formatter
      class OptionValidateError
        #
        # Print the `Msf::OptionValidateError` error in a human readable format
        #
        # @param mod  [::Msf::Framework, ::Msf::Simple::Framework]  The mod
        # @param error [::Msf::OptionValidateError] The error to print
        def self.print_error(mod, error)
          raise ArgumentError, "invalid error type #{error.class}, expected ::Msf::OptionValidateError" unless error.is_a?(::Msf::OptionValidateError)

          error.options.each do |option|
            # Assign module examples unless the value is not available within options as it wasn't created as an option object.
            # example: value assigned directly to datastore without being created as an options object via `OptString.new` or similar.
            # See spec/lib/msf/ui/console/command_dispatcher/exploit_spec.rb:279
            option_examples = mod.options[option].nil? ? [] : mod.options[option].examples
            option_value = mod.datastore[option]

            if error.reasons.empty?
              if option_examples.empty? && option_value.blank?
                mod.print_error("#{error.class} The following option failed to validate: A value is required for option '#{option}'.")
              elsif option_examples.empty?
                mod.print_error("#{error.class} The following option failed to validate: Value '#{option_value}' is not valid for option '#{option}'.")
              elsif option_value.blank?
                mod.print_error("#{error.class} The following option failed to validate: A value is required for option '#{option}'. Example value: #{option_examples.join(', ')}")
              else
                mod.print_error("#{error.class} The following option failed to validate: Value '#{option_value}' is not valid for option '#{option}'. Example value: #{option_examples.join(', ')}")
              end
            else
              mod.print_error("#{error.class} The following options failed to validate:")
              option.sort.each do |option_name|
                reasons = error.reasons[option_name]
                if reasons
                  mod.print_error("Invalid option #{option_name}: #{reasons.join(', ')}")
                else
                  mod.print_error("Invalid option #{option_name}")
                end
              end
            end
          end
        end
      end
    end
  end
end
