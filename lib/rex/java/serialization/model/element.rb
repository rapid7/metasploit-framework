module Rex
  module Java
    module Serialization
      module Model
        class Element

          # Unserializes a Java::Serialization::Model::Element
          #
          # @param io [IO] the io to read from
          # @return [Java::Serialization::Model::Element] if deserialization is possible
          # @return [nil] if deserialization isn't possible
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