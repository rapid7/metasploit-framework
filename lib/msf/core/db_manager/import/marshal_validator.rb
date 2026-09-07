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
        MarshalValidationError = Msf::DBManager::Import::MarshalValidationError

        # Type bytes that always instantiate named classes — unconditionally blocked.
        UNSAFE_TYPES = Set.new(%w[o c m C S e U d].map(&:ord)).freeze

        # Default classes permitted for the 'u' (_dump/_load) serialization type.
        DEFAULT_PERMITTED_CLASSES = %w[].freeze

        # Prevent deeply nested input from exhausting the Ruby call stack while
        # the validator recursively walks compound values.
        MAX_NESTING_DEPTH = 512

        # @param data [String] raw Marshal binary data
        # @param permitted_classes [Array<String>] class names allowed for
        #   _dump/_load ('u') deserialization. Defaults to {DEFAULT_PERMITTED_CLASSES}.
        def initialize(data, permitted_classes: DEFAULT_PERMITTED_CLASSES)
          @bytes = String.new(data).bytes
          @pos = 0
          @object_count = 0
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
          # Validate and load the same plain String snapshot. In particular, do
          # not let a String subclass supply different data through #bytes, and
          # do not leave a window in which another thread can mutate the input.
          payload = String.new(data).freeze
          new(payload, permitted_classes: permitted_classes).validate!
          Marshal.load(payload) # rubocop:disable Security/MarshalLoad -- payload has been structurally validated above
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
            (-c).times do |i|
              n &= ~(0xff << (8 * i))
              n |= read_byte << (8 * i)
            end
            n
          else
            # Small integer: encoded directly
            c > 0 ? c - 5 : c + 5
          end
        end

        def read_marshal_length
          n = read_marshal_int
          raise MarshalValidationError, "Negative length #{n} at offset #{@pos}" if n.negative?

          n
        end

        def register_symbol(name)
          (@symbol_cache ||= []) << name
          name
        end

        # Skip n raw bytes (used to skip over string/symbol content)
        def skip_bytes(count)
          raise MarshalValidationError, "Negative skip #{count} at offset #{@pos}" if count.negative?
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
            len = read_marshal_length
            name_bytes = @bytes[@pos, len]
            raise MarshalValidationError, "Unexpected end of Marshal stream reading class name at offset #{@pos}" if name_bytes.nil? || name_bytes.length < len

            @pos += len
            register_symbol(name_bytes.pack('C*'))
          when 0x3B # ';' — Symbol link (back-reference)
            read_symbol_link
          else
            raise MarshalValidationError,
                  "Expected symbol for class name but got 0x#{type.to_s(16)} at offset #{@pos - 1}"
          end
        end

        def read_symbol_link
          idx = read_marshal_length
          cached = (@symbol_cache ||= [])[idx]
          raise MarshalValidationError, "Invalid symbol back-reference #{idx} at offset #{@pos}" unless cached

          cached
        end

        def register_object
          @object_count += 1
        end

        def read_object_link
          idx = read_marshal_length
          if idx >= @object_count
            raise MarshalValidationError, "Invalid object back-reference #{idx} at offset #{@pos}"
          end
        end

        # Validate a single value at the current position.
        def validate_value(depth = 0, defer_userdef_entry: false)
          if depth > MAX_NESTING_DEPTH
            raise MarshalValidationError, "Marshal nesting exceeds maximum depth of #{MAX_NESTING_DEPTH} at offset #{@pos}"
          end

          type = read_byte
          deferred_object_entry = false

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
            sign = read_byte
            unless [0x2B, 0x2D].include?(sign) # '+' or '-'
              raise MarshalValidationError, "Invalid Bignum sign 0x#{sign.to_s(16)} at offset #{@pos - 1}"
            end

            len = read_marshal_length # number of 16-bit shorts
            skip_bytes(len * 2)
            register_object
          when 0x66 # 'f' — Float
            len = read_marshal_length
            skip_bytes(len)
            register_object
          when 0x3A # ':' — Symbol
            len = read_marshal_length
            name_bytes = @bytes[@pos, len]
            raise MarshalValidationError, 'Unexpected end of Marshal stream reading symbol' if name_bytes.nil? || name_bytes.length < len

            register_symbol(name_bytes.pack('C*'))
            skip_bytes(len)
          when 0x3B # ';' — Symbol link (back-reference)
            read_symbol_link
          when 0x22 # '"' — String (raw, no instance vars)
            len = read_marshal_length
            skip_bytes(len)
            register_object
          when 0x49 # 'I' — Instance variables wrapper
            deferred_object_entry = validate_value(depth + 1, defer_userdef_entry: true)
            num_ivars = read_marshal_length
            num_ivars.times do
              validate_value(depth + 1) # ivar name (symbol)
              validate_value(depth + 1) # ivar value
            end
            register_object if deferred_object_entry
            deferred_object_entry = false
          when 0x5B # '[' — Array
            count = read_marshal_length
            register_object
            count.times { validate_value(depth + 1) }
          when 0x7B # '{' — Hash
            count = read_marshal_length
            register_object
            count.times do
              validate_value(depth + 1) # key
              validate_value(depth + 1) # value
            end
          when 0x7D # '}' — Hash with default
            count = read_marshal_length
            register_object
            count.times do
              validate_value(depth + 1) # key
              validate_value(depth + 1) # value
            end
            validate_value(depth + 1) # default value
          when 0x40 # '@' — Object link (back-reference)
            read_object_link
          when 0x75 # 'u' — _dump/_load custom serialization
            class_name = read_class_name
            unless @permitted_classes.include?(class_name)
              raise MarshalValidationError,
                    "Unsafe Marshal _dump/_load class '#{class_name}' " \
                    "at offset #{@pos} — refusing to deserialize"
            end
            # Skip the _dump data payload
            len = read_marshal_length
            skip_bytes(len)
            if defer_userdef_entry
              deferred_object_entry = true
            else
              register_object
            end
          else
            raise MarshalValidationError,
                  "Unknown Marshal type byte 0x#{type.to_s(16)} (#{type.chr.inspect}) " \
                  "at offset #{@pos - 1} — refusing to deserialize"
          end

          deferred_object_entry
        end
      end
    end
  end
end
