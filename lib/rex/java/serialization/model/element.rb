module Rex
  module Java
    module Serialization
      module Model
        class Element
          def self.decode(io)
            elem = self.new
            elem.decode(io)
          end

          def initialize

          end

          def decode(io)
            self
          end

          def encode
            ''
          end
        end
      end
    end
  end
end