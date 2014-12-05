module Rex
  module Java
    module Serialization
      module Model
        class Element

          attr_accessor :stream

          # Deserializes a Java::Serialization::Model::Element
          #
          # @param io [IO] the io to read from
          # @return [Java::Serialization::Model::Element] if deserialization succeeds
          # @return [nil] if deserialization doesn't succeed
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