module Net
  module SSH
    module Verifiers

      # This host key verifier simply allows every key it sees, without
      # any verification. This is simple, but very insecure because it
      # exposes you to MiTM attacks.
      class Never
        # Returns true.
        def verify(arguments)
          true
        end
      end

    end
  end
end
