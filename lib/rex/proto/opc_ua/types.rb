# -*- coding: binary -*-

require 'bindata'

module Rex::Proto::OpcUa::Types
  # OPC-UA encodes String and ByteString identically on the wire: a signed
  # Int32 length prefix followed by that many bytes. A length of -1 denotes a
  # null value, which the specification treats as distinct from a length of 0
  # denoting an empty value. See OPC-UA Specification Part 6, section 5.2.2.
  #
  # BinData has no native type for a length prefix that doubles as a null
  # sentinel, so the read and write paths are implemented directly against
  # BasePrimitive. This follows LengthPrefixedString in
  # Msf::Util::DotNetDeserialization::Types, which solves the equivalent
  # problem for the .NET remoting 7-bit length prefix.
  #
  # Null is represented in Ruby as nil and empty as an empty string, so the
  # distinction survives a decode and re-encode unchanged.
  class OpcUaByteString < BinData::BasePrimitive
    # The length prefix denoting a null value.
    NULL_LENGTH = -1

    # BasePrimitive#assign rejects nil outright, but null is a legitimate value
    # here and is what several request fields are required to carry, such as
    # the ClientNonce and SenderCertificate of an OpenSecureChannelRequest sent
    # under SecurityPolicy None. Accept nil and store it as the null value.
    #
    # BinData::Base#initialize skips #assign when constructed with nil, so
    # .new(nil) already yields a null; this makes the explicit assignment and
    # field setter paths agree with it.
    def assign(val)
      return @value = nil if val.nil?

      super
    end

    private

    def value_to_binary_string(val)
      return [NULL_LENGTH].pack('l<') if val.nil?

      raw = val.to_s.dup.force_encoding('BINARY')
      [raw.bytesize].pack('l<') + raw
    end

    def read_and_return_value(io)
      length = io.readbytes(4).unpack1('l<')
      # The specification defines only -1, but any negative length is read as
      # null. A scanner should not discard an otherwise intact response over an
      # out of spec sentinel whose intent is unambiguous.
      return nil if length.negative?

      io.readbytes(length)
    end

    def sensible_default
      nil
    end
  end

  # A String has the ByteString wire format with UTF-8 content.
  #
  # The bytes arrive from an unauthenticated server, so invalid sequences are
  # scrubbed rather than raised on. Note that scrubbing is not the same as
  # transcoding: String#encode from BINARY to UTF-8 would treat every byte at
  # or above 0x80 as undefined and replace it, turning a valid "cafe" with an
  # e-acute into "caf??". Tagging the bytes UTF-8 and scrubbing preserves valid
  # multi-byte text and replaces only what is genuinely malformed.
  class OpcUaString < OpcUaByteString
    # Substituted for each malformed byte sequence.
    REPLACEMENT_CHARACTER = '?'

    private

    def read_and_return_value(io)
      raw = super
      return nil if raw.nil?

      raw.force_encoding('UTF-8').scrub(REPLACEMENT_CHARACTER)
    end
  end

  # An array is an Int32 element count followed by that many elements. As with
  # String and ByteString a negative count denotes null, which the
  # specification treats as distinct from a count of zero denoting an empty
  # array. See OPC-UA Specification Part 6, section 5.2.5.
  #
  # The element type is supplied as the ordinary BinData :type parameter at the
  # declaration site, and :max_length caps how many elements will be read:
  #
  #   opc_ua_array :endpoints, type: :opc_ua_endpoint_description, max_length: 64
  #
  # The ceiling is load bearing rather than defensive dressing. The count comes
  # off the wire from an unauthenticated server and BinData allocates an object
  # per element, so without it a claimed count of 2**31 - 1 would be attempted.
  #
  # A null array presents as empty, so it can be iterated without a nil check;
  # #null? preserves the wire distinction so that a decode and re-encode is
  # byte for byte unchanged.
  class OpcUaArray < BinData::Array
    # The element count denoting a null array.
    NULL_LENGTH = -1

    # Applied when a declaration site does not give its own ceiling. There is
    # deliberately no way to switch the ceiling off; a declaration site that
    # legitimately needs more raises it explicitly. BinData rejects a nil
    # parameter value in any case.
    DEFAULT_MAX_LENGTH = 512

    default_parameter max_length: DEFAULT_MAX_LENGTH

    # BinData::Array selects its read strategy in #initialize_shared_instance
    # and installs it with #extend, which places it ahead of this class in the
    # singleton ancestry. Overriding #do_read as an ordinary instance method is
    # therefore not merely wrong but silently wrong: BinData::Array's
    # #sanitize_parameters! defaults :initial_length to 0 whenever neither it
    # nor :read_until was given, so InitialLengthPlugin is always installed,
    # and every read would return an empty array with nothing raised.
    # Extending after super is what puts the count prefix ahead of it.
    def initialize_shared_instance
      super
      extend CountPrefixPlugin
    end

    def initialize_instance
      super
      @null = false
    end

    # @return [Boolean] whether this array was read as, or assigned, null.
    def null?
      @null
    end

    # BinData::Array#assign rejects nil, so null has to be taken here and
    # stored as an empty element list flagged as null.
    def assign(array)
      @null = array.nil?
      super(@null ? [] : array)
    end

    # The count prefix. This has to be a module extended onto the instance
    # rather than methods on the class; see #initialize_shared_instance.
    module CountPrefixPlugin
      def do_read(io)
        count = io.readbytes(4).unpack1('l<')
        @element_list = []

        if count.negative?
          @null = true
          return
        end

        @null = false
        max_length = eval_parameter(:max_length)
        if count > max_length
          raise BinData::ValidityError,
                "array length #{count} exceeds the #{max_length} element ceiling for #{debug_name}"
        end

        count.times { append_new_element.do_read(io) }
      end

      def do_write(io)
        io.writebytes([@null ? NULL_LENGTH : length].pack('l<'))
        super unless @null
      end

      def do_num_bytes
        @null ? 4 : 4 + super
      end
    end
  end
end
