module Metasploit
  module Framework
    module PasswordCracker

      # This class is the generic Exception raised by a {Wordlist} when
      # it fails validation. It rolls up all validation errors into a
      # single exception so that all errors can be dealt with at once.
      class InvalidWordlist < StandardError
        attr_reader :model

        def initialize(model)
          @model = model

          errors = @model.errors.full_messages.join(', ')
          super(errors)
        end
      end
    end
  end
end
