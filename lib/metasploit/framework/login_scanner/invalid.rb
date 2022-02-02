module Metasploit
  module Framework
    module LoginScanner

      # This class is the generic Exception raised by LoginScanners when
      # they fail validation. It rolls up all validation errors into a
      # single exception so that all errors can be dealt with at once.
      class Invalid < StandardError

        attr_reader :model

        def initialize(model)
          @model = model

          errors = @model.errors.full_messages.join(', ')
          errors << " (#{model.class.to_s})"
          super(errors)
        end
      end

    end
  end
end
