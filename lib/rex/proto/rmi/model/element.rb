# -*- coding: binary -*-

module Rex
  module Proto
    module Rmi
      module Model
        class Element

          include Rex::Proto::Rmi::Model

          def self.attr_accessor(*vars)
            @attributes ||= []
            @attributes.concat vars
            super(*vars)
          end

          # Retrieves the element class fields
          #
          # @return [Array]
          def self.attributes
            @attributes
          end

          # Creates a Rex::Proto::Rmi::Model::Element with data from the IO.
          #
          # @param io [IO] the IO to read data from
          # @return [Rex::Proto::Rmi::Model::Element]
          def self.decode(io)
            elem = self.new
            elem.decode(io)

            elem
          end

          def initialize(options = {})
            self.class.attributes.each do |attr|
              if options.has_key?(attr)
                m = (attr.to_s + '=').to_sym
                self.send(m, options[attr])
              end
            end
          end

          # Retrieves the element instance fields
          #
          # @return [Array]
          def attributes
            self.class.attributes
          end

          # Decodes the Rex::Proto::Rmi::Model::Element from the input.
          #
          # @raise [NoMethodError]
          # @return [Rex::Proto::Rmi::Model::Element]
          def decode(io)
            self.class.attributes.each do |attr|
              dec_method = ("decode_#{attr}").to_sym
              decoded = self.send(dec_method, io)
              assign_method = (attr.to_s + '=').to_sym
              self.send(assign_method, decoded)
            end

            self
          end

          # Encodes the Rex::Proto::Rmi::Model::Element into an String.
          #
          # @raise [NoMethodError]
          # @return [String]
          def encode
            encoded = ''
            self.class.attributes.each do |attr|
              m = ("encode_#{attr}").to_sym
              encoded << self.send(m) if self.send(attr)
            end

            encoded
          end

          private

          # Reads a byte from an IO
          #
          # @param io [IO] the IO to read from
          # @return [Integer]
          # @raise [Rex::Proto::Rmi::DecodeError] if the byte can't be read from io
          def read_byte(io)
            raw = io.read(1)
            raise Rex::Proto::Rmi::DecodeError, 'Failed to read byte' unless raw

            raw.unpack('c')[0]
          end

          # Reads a two bytes short from an IO
          #
          # @param io [IO] the IO to read from
          # @return [Integer]
          # @raise [Rex::Proto::Rmi::DecodeError] if the short can't be read from io
          def read_short(io)
            raw = io.read(2)

            unless raw && raw.length == 2
              raise Rex::Proto::Rmi::DecodeError, 'Failed to read short'
            end

            raw.unpack('s>')[0]
          end

          # Reads a four bytes int from an IO
          #
          # @param io [IO] the IO to read from
          # @return [Integer]
          # @raise [Rex::Proto::Rmi::DecodeError] if the int can't be read from io
          def read_int(io)
            raw = io.read(4)

            unless raw && raw.length == 4
              raise Rex::Proto::Rmi::DecodeError, 'Failed to read int'
            end

            raw.unpack('l>')[0]
          end

          # Reads a 8 bytes long from an IO
          #
          # @param io [IO] the IO to read from
          # @return [Integer]
          # @raise [Rex::Proto::Rmi::DecodeError] if the long can't be read from io
          def read_long(io)
            raw = io.read(8)

            unless raw && raw.length == 8
              raise Rex::Proto::Rmi::DecodeError, 'Failed to read long'
            end

            raw.unpack('q>')[0]
          end

          # Reads an string from an IO
          #
          # @param io [IO] the IO to read from
          # @param length [Integer] the string length
          # @return [String]
          # @raise [Rex::Proto::Rmi::DecodeError] if the string can't be read from io
          def read_string(io, length)
            raw = io.read(length)

            unless raw && raw.length == length
              raise Rex::Proto::Rmi::DecodeError, 'Failed to read string'
            end

            raw
          end
        end
      end
    end
  end
end