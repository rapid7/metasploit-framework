# -*- coding: binary -*-

module Msf
  module Simple
    module Exception
      #
      # Print the `Msf::OptionValidateError` error in a human readable format
      #
      # @param error  [::Msf::Framework, ::Msf::Simple::Framework]  The error to print
      # @param error [::Msf::OptionValidateError] The error to print
      def self.print_option_validate_error(mod, error)
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
