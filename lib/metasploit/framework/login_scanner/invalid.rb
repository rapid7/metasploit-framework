module Metasploit
  module Framework
    module LoginScanner

      class Invalid < StandardError

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
