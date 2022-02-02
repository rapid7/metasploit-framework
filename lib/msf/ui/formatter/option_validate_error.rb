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

          if error.reasons.empty?
            mod.print_error("#{error.class} The following options failed to validate: #{error.options.join(', ')}")
          else
            mod.print_error("#{error.class} The following options failed to validate:")
            error.options.sort.each do |option_name|
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
