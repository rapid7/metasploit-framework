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

  # OPC-UA DateTime: a signed Int64 count of 100 nanosecond ticks since
  # 1601-01-01 00:00:00 UTC, the same epoch and resolution as a Windows
  # FILETIME. See OPC-UA Specification Part 6, section 5.2.2.5.
  #
  # The Ruby value is the raw tick count rather than a Time, so that a decode
  # and re-encode is byte for byte unchanged whatever the server sent, including
  # values a Time cannot hold. #to_time converts on demand for the callers that
  # want a date rather than a number.
  class OpcUaDateTime < BinData::Int64le
    # Ticks in one second.
    TICKS_PER_SECOND = 10_000_000

    # Seconds between the OPC-UA epoch of 1601-01-01 and the Unix epoch of
    # 1970-01-01. This is the 134774 days between the two dates in seconds,
    # which is worth stating because the number is otherwise unverifiable by
    # inspection:
    #
    #   (Date.new(1970, 1, 1) - Date.new(1601, 1, 1)).to_i * 86400 == 11_644_473_600
    UNIX_EPOCH_SECONDS = 11_644_473_600

    # The same offset in ticks.
    UNIX_EPOCH_TICKS = UNIX_EPOCH_SECONDS * TICKS_PER_SECOND

    # @param time [Time] the time to encode.
    # @return [Integer] the tick count for that time.
    def self.from_time(time)
      ((time.to_r * TICKS_PER_SECOND) + UNIX_EPOCH_TICKS).to_i
    end

    # @return [Integer] the tick count for the current time, for the Timestamp
    #   of a request being built.
    def self.now
      from_time(::Time.now)
    end

    # @return [Time] this timestamp as a UTC Time. The conversion goes through
    #   a Rational rather than a Float, so no tick is lost on the way.
    def to_time
      ::Time.at(Rational(snapshot - UNIX_EPOCH_TICKS, TICKS_PER_SECOND)).utc
    end
  end

  # NodeId, which names a node in a server's address space and is also how every
  # service names its own encoding. See OPC-UA Specification Part 6,
  # section 5.2.2.9.
  #
  # The leading byte selects the identifier form in its low nibble. Bits 0x80
  # and 0x40 add a trailing NamespaceUri and ServerIndex; those belong to the
  # ExpandedNodeId form, and are accepted here because the two forms are not
  # distinguishable from the bytes alone, so a reader that rejected them would
  # fail against a server that sends one where this expects a NodeId.
  #
  # Only the TwoByte and FourByte forms appear in the captures under
  # spec/file_fixtures/opc_ua. The other four, and both flags, are carried over
  # unchanged from the reader in the module this library replaces; their specs
  # are hand-built and are marked as such.
  class OpcUaNodeId < BinData::Record
    endian :little

    # Identifier forms, held in the low nibble of the encoding byte.
    TWO_BYTE = 0x00
    FOUR_BYTE = 0x01
    NUMERIC = 0x02
    STRING = 0x03
    GUID = 0x04
    BYTE_STRING = 0x05

    # Selects the identifier form.
    FORM_MASK = 0x0F
    # Set when a NamespaceUri String follows the identifier.
    NAMESPACE_URI_FLAG = 0x80
    # Set when a ServerIndex UInt32 follows.
    SERVER_INDEX_FLAG = 0x40

    # A GUID identifier is 16 raw bytes.
    GUID_LEN = 16

    # The identifier forms this understands. An encoding byte naming anything
    # else is rejected here rather than at the choice below, so that it fails as
    # a BinData::ValidityError alongside every other decode failure instead of
    # as a bare IndexError from the choice.
    FORMS = [TWO_BYTE, FOUR_BYTE, NUMERIC, STRING, GUID, BYTE_STRING].freeze

    uint8 :encoding_byte, assert: -> { FORMS.include?(value & FORM_MASK) }

    choice :body, selection: -> { encoding_byte & FORM_MASK } do
      # TwoByte carries no NamespaceIndex at all: it is namespace 0 by
      # definition, which is why it can encode a NodeId in two bytes.
      struct TWO_BYTE do
        uint8 :identifier
      end
      struct FOUR_BYTE do
        uint8  :namespace_index
        uint16 :identifier
      end
      struct NUMERIC do
        uint16 :namespace_index
        uint32 :identifier
      end
      struct STRING do
        uint16        :namespace_index
        opc_ua_string :identifier
      end
      struct GUID do
        uint16 :namespace_index
        string :identifier, length: GUID_LEN
      end
      struct BYTE_STRING do
        uint16             :namespace_index
        opc_ua_byte_string :identifier
      end
    end

    opc_ua_string :namespace_uri, onlyif: -> { (encoding_byte & NAMESPACE_URI_FLAG) != 0 }
    uint32        :server_index, onlyif: -> { (encoding_byte & SERVER_INDEX_FLAG) != 0 }

    # Build the FourByte form, which is what every service identifier in this
    # library uses. The default instance is already the null NodeId, the TwoByte
    # form with identifier 0, so there is no helper for that.
    #
    # @param identifier [Integer] the numeric identifier.
    # @param namespace_index [Integer] the namespace, 0 for the standard set.
    # @return [OpcUaNodeId]
    def self.four_byte(identifier, namespace_index: 0)
      new(encoding_byte: FOUR_BYTE, body: { namespace_index: namespace_index, identifier: identifier })
    end

    # @return [Integer] the NamespaceIndex, which the TwoByte form leaves
    #   implicit at 0.
    def namespace_index
      body.respond_to?(:namespace_index) ? body.namespace_index.snapshot : 0
    end

    # @return [Integer, String, nil] the identifier. Its type follows the form:
    #   an Integer for the three numeric forms, a String for the others.
    def identifier
      body.identifier.snapshot
    end
  end

  # ExtensionObject: a NodeId naming the encoding of the body, an encoding byte,
  # and the body itself where there is one. See OPC-UA Specification Part 6,
  # section 5.2.2.15.
  #
  # Every ExtensionObject in the captures is the empty form, a null TypeId with
  # encoding 0x00, which is how an absent AdditionalHeader is sent.
  class OpcUaExtensionObject < BinData::Record
    endian :little

    # No body follows the encoding byte.
    NO_BODY = 0x00
    # The body is a ByteString.
    BYTE_STRING_BODY = 0x01
    # The body is an XmlElement, which has the ByteString wire format.
    XML_ELEMENT_BODY = 0x02

    # The encodings this understands. Anything else is rejected on read rather
    # than being skipped, because the length of an unknown body is unknown and
    # guessing at it would desynchronise everything that follows.
    ENCODINGS = [NO_BODY, BYTE_STRING_BODY, XML_ELEMENT_BODY].freeze

    opc_ua_node_id :type_id
    uint8          :encoding, assert: -> { ENCODINGS.include?(value) }

    choice :body, selection: :encoding do
      string             NO_BODY, length: 0
      opc_ua_byte_string BYTE_STRING_BODY
      opc_ua_byte_string XML_ELEMENT_BODY
    end
  end

  # DiagnosticInfo, in the only form this library will read: empty. See OPC-UA
  # Specification Part 6, section 5.2.2.12.
  #
  # Every request sent from here sets ReturnDiagnostics to zero, so a server
  # that returns a populated DiagnosticInfo has answered a question it was not
  # asked. The seven optional fields it would then carry, one of them a nested
  # DiagnosticInfo, cannot be exercised against any capture, so reading one
  # raises rather than being decoded against a structure taken on trust.
  class OpcUaDiagnosticInfo < BinData::BasePrimitive
    # The encoding mask of an empty DiagnosticInfo: no optional field present.
    EMPTY = 0x00

    private

    def value_to_binary_string(val)
      raise BinData::ValidityError, format('DiagnosticInfo can only be written empty, not 0x%02X', val) unless val == EMPTY

      [EMPTY].pack('C')
    end

    def read_and_return_value(io)
      mask = io.readbytes(1).unpack1('C')
      unless mask == EMPTY
        raise BinData::ValidityError,
              format('DiagnosticInfo encoding mask 0x%02X, but no diagnostics were requested', mask)
      end

      mask
    end

    def sensible_default
      EMPTY
    end
  end
end
