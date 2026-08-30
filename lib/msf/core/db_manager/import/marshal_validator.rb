# frozen_string_literal: true

require 'set'

module Msf
  class DBManager
    module Import
      # Raised when the Marshal stream validator detects an unsafe type
      # byte that would trigger class instantiation during deserialization.
      class MarshalValidationError < StandardError; end

      # Walks a Marshal byte stream structurally, reading type bytes only in
      # type positions and skipping over data payloads. Rejects any stream
      # that attempts to instantiate a named class (object, struct, custom
      # marshal, module extension, etc.).
      #
      # This runs BEFORE Marshal.load so no objects are ever instantiated
      # from an unsafe payload.
      #
      # Reference: https://ruby-doc.org/3.3/Marshal.html
      # Reference: https://github.com/ruby/ruby/blob/master/doc/marshal/marshal.md
      class MarshalValidator
        # Type bytes that always instantiate named classes — unconditionally blocked.
        UNSAFE_TYPES = Set.new(%w[o c m C S e U d].map(&:ord)).freeze

        # Default classes permitted for the 'u' (_dump/_load) serialization type.
        DEFAULT_PERMITTED_CLASSES = %w[].freeze

        # @param data [String] raw Marshal binary data
        # @param permitted_classes [Array<String>] class names allowed for
        #   _dump/_load ('u') deserialization. Defaults to {DEFAULT_PERMITTED_CLASSES}.
        def initialize(data, permitted_classes: DEFAULT_PERMITTED_CLASSES)
          @bytes = data.bytes
          @pos = 0
          @permitted_classes = Set.new(permitted_classes)
        end

        # Validate the entire stream. Raises MarshalValidationError if unsafe.
        # @return [true]
        def validate!
          read_version
          validate_value
          true
        end

        # Convenience method: validate and then load.
        # @param data [String] raw Marshal binary data
        # @param permitted_classes [Array<String>] class names allowed for
        #   _dump/_load ('u') deserialization. Defaults to {DEFAULT_PERMITTED_CLASSES}.
        # @return [Object] the deserialized object (only primitives + permitted classes)
        # @raise [MarshalValidationError] if the payload contains disallowed class references
        def self.safe_load(data, permitted_classes: DEFAULT_PERMITTED_CLASSES)
          new(data, permitted_classes: permitted_classes).validate!
          Marshal.load(data)
        end

        # Check whether the given data starts with the Marshal 4.8 version
        # header, indicating it is a Marshal-serialized payload.
        #
        # @param data [String] raw binary data
        # @return [Boolean]
        def self.marshalled_data?(data)
          data.length >= 2 && data.getbyte(0) == 4 && data.getbyte(1) == 8
        end

        private

        def read_byte
          raise MarshalValidationError, "Unexpected end of Marshal stream at offset #{@pos}" if @pos >= @bytes.length

          b = @bytes[@pos]
          @pos += 1
          b
        end

        def read_version
          major = read_byte
          minor = read_byte
          unless major == 4 && minor == 8
            raise MarshalValidationError, "Unsupported Marshal version #{major}.#{minor}"
          end
        end

        # Read a Marshal-encoded integer (used for lengths, counts, etc.)
        # This follows Ruby's Marshal integer encoding scheme.
        def read_marshal_int
          c = read_byte
          c -= 256 if c > 127 # sign-extend

          if c == 0
            0
          elsif c > 0 && c <= 4
            # c bytes follow, little-endian positive
            n = 0
            c.times { |i| n |= read_byte << (8 * i) }
            n
          elsif c >= -4 && c < 0
            # -c bytes follow, little-endian negative
            n = -1
            (-c).times { |i| n &= ~(0xff << (8 * i)); n |= read_byte << (8 * i) }
            n
          else
            # Small integer: encoded directly
            c > 0 ? c - 5 : c + 5
          end
        end

        # Skip n raw bytes (used to skip over string/symbol content)
        def skip_bytes(count)
          raise MarshalValidationError, "Unexpected end of Marshal stream at offset #{@pos}" if @pos + count > @bytes.length

          @pos += count
        end

        # Read a class/module name from the stream. In Marshal format,
        # class names are encoded as symbols (`:` or `;` back-reference).
        # @return [String] the class name
        def read_class_name
          type = read_byte
          case type
          when 0x3A # ':' — Symbol (inline)
            len = read_marshal_int
            name_bytes = @bytes[@pos, len]
            raise MarshalValidationError, "Unexpected end of Marshal stream reading class name at offset #{@pos}" if name_bytes.nil? || name_bytes.length < len

            @pos += len
            (@symbol_cache ||= []) << name_bytes.pack('C*')
            @symbol_cache.last
          when 0x3B # ';' — Symbol link (back-reference)
            idx = read_marshal_int
            cached = (@symbol_cache ||= [])[idx]
            raise MarshalValidationError, "Invalid symbol back-reference #{idx} at offset #{@pos}" unless cached

            cached
          else
            raise MarshalValidationError,
                  "Expected symbol for class name but got 0x#{type.to_s(16)} at offset #{@pos - 1}"
          end
        end

        # Validate a single value at the current position.
        def validate_value
          type = read_byte

          if UNSAFE_TYPES.include?(type)
            raise MarshalValidationError,
                  "Unsafe Marshal type byte 0x#{type.to_s(16)} (#{type.chr.inspect}) " \
                  "at offset #{@pos - 1} — refusing to deserialize"
          end

          case type
          when 0x30 # '0' — nil
            # no data
          when 0x54 # 'T' — true
            # no data
          when 0x46 # 'F' — false
            # no data
          when 0x69 # 'i' — Integer (Fixnum)
            read_marshal_int
          when 0x6C # 'l' — Integer (Bignum)
            read_byte # sign byte (+/-)
            len = read_marshal_int # number of 16-bit shorts
            skip_bytes(len * 2)
          when 0x66 # 'f' — Float
            len = read_marshal_int
            skip_bytes(len)
          when 0x3A # ':' — Symbol
            len = read_marshal_int
            skip_bytes(len)
          when 0x3B # ';' — Symbol link (back-reference)
            read_marshal_int
          when 0x22 # '"' — String (raw, no instance vars)
            len = read_marshal_int
            skip_bytes(len)
          when 0x49 # 'I' — Instance variables wrapper
            validate_value # the wrapped object
            num_ivars = read_marshal_int
            num_ivars.times do
              validate_value # ivar name (symbol)
              validate_value # ivar value
            end
          when 0x5B # '[' — Array
            count = read_marshal_int
            count.times { validate_value }
          when 0x7B # '{' — Hash
            count = read_marshal_int
            count.times do
              validate_value # key
              validate_value # value
            end
          when 0x7D # '}' — Hash with default
            count = read_marshal_int
            count.times do
              validate_value # key
              validate_value # value
            end
            validate_value # default value
          when 0x40 # '@' — Object link (back-reference)
            read_marshal_int
          when 0x75 # 'u' — _dump/_load custom serialization
            class_name = read_class_name
            unless @permitted_classes.include?(class_name)
              raise MarshalValidationError,
                    "Unsafe Marshal _dump/_load class '#{class_name}' " \
                    "at offset #{@pos} — refusing to deserialize"
            end
            # Skip the _dump data payload
            len = read_marshal_int
            skip_bytes(len)
          else
            raise MarshalValidationError,
                  "Unknown Marshal type byte 0x#{type.to_s(16)} (#{type.chr.inspect}) " \
                  "at offset #{@pos - 1} — refusing to deserialize"
          end
        end
      end
    end
  end
end
