# -*- coding: binary -*-

module Rex
  module Java
    module Serialization
      module Model
        class Element

          attr_accessor :stream

          # Deserializes a Rex::Java::Serialization::Model::Element
          #
          # @param io [IO] the io to read from
          # @return [Rex::Java::Serialization::Model::Element] if deserialization succeeds
          # @return [nil] if deserialization doesn't succeed
          def self.decode(io, stream = nil)
            elem = self.new(stream)
            elem.decode(io)
          end

          # @param stream [Rex::Java::Serialization::Model::Stream] the stream where it belongs to
          def initialize(stream = nil)
            self.stream = stream
          end

          def decode(io)
            self
          end

          def encode
            ''
          end

          # Creates a print-friendly string representation
          #
          # @return [String]
          def to_s
            self.class.name.split('::').last
          end
        end
      end
    end
  end
end