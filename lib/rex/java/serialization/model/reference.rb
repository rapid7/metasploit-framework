module Rex
  module Java
    module Serialization
      module Model
        class Reference < Element

          attr_accessor :handler

          def initialize(stream = nil)
            super(stream)
            handler = 0
          end

          def decode(io)
            handler_raw = io.read(4)
            unless handler_raw && handler_raw.length == 4
              raise ::RuntimeError, 'Failed to unserialize Reference'
            end

            self.handler = handler_raw.unpack('N')[0]

            self
          end
        end
      end
    end
  end
end