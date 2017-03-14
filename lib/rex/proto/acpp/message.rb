# -*- coding: binary -*-

module Rex
module Proto
module ACPP
  # From what I've been able to gather from the very limited findings on the
  # web about this protocol, playing with it against a real Airport device and
  # referencing the airport-utils package in Debian/Ubuntu, the format of (at
  # least) the login message is:
  #
  # acpp            # the header tag, always exactly acpp (4 bytes)
  # unknown1        # unknown 4-byte field.  Almost always 0x00000001
  # messageChecksum # checksum of the message, 4 bytes
  # payloadChecksum # checksum of the payload, 4 bytes
  # payloadSize     # size of the payload, 4 bytes
  # unknown2        # unknown 8-byte field.  probably some sort of
  #                   request/response identifier.  generally 0 for requests, 1 for replies
  # messageType     # the type of message, 4 bytes.  see below.
  # status          # the status of this message, 4 bytes.
  #                   generally 0 for success and !0 for failure.
  # unknown3        # unknown 12-byte field, seemingly always 0.  Probably 'reserved'
  # password        # 32-byte password, 'encrypted' by XOR'ing it with a 256-byte static key (see XOR_KEY)
  # unknown4        # unknown 48-byte field, always 0.
  #
  # There are several possible message types:
  #
  #   * 20 -- retrieve settings (payload is some list of settings to obtain)
  #   * 21 -- update setttings (and if the 'acRB' setting is set, it reboots)
  #   * 3  -- Upload firmware
  #
  # TODO: if you find more, add them above.
  #
  # When the message type is anything other than 20 or 3, payloadSize is set to -1 and
  # payloadChecksum is set to 1.  It may be a bug that 21 doesn't look at the
  # checksum.  Adler32 is used to compute the checksum.
  #
  # The message payload is a bit of an unknown right now, as it *seems* like
  # the payload always comes in a subsequent request.  Simply appending
  # a payload to the existing message does not appear to work (but this needs
  # more testing)

  # This was taken from airport-util's AirportInforRecord for ease of copying, but can
  # also be obtained by XOR'ing the null-padded known plain text with the appropriate 32-byte
  # ciphertext from an airport-util request
  XOR_KEY = [
    14, 57, -8, 5, -60, 1, 85, 79, 12, -84,
    -123, 125, -122, -118, -75, 23, 62, 9, -56, 53,
    -12, 49, 101, 127, 60, -100, -75, 109, -106, -102,
    -91, 7, 46, 25, -40, 37, -28, 33, 117, 111,
    44, -116, -91, -99, 102, 106, 85, -9, -34, -23,
    40, -43, 20, -47, -123, -97, -36, 124, 85, -115,
    118, 122, 69, -25, -50, -7, 56, -59, 4, -63,
    -107, -113, -52, 108, 69, -67, 70, 74, 117, -41,
    -2, -55, 8, -11, 52, -15, -91, -65, -4, 92,
    117, -83, 86, 90, 101, -57, -18, -39, 24, -27,
    36, -31, -75, -81, -20, 76, 101, -35, 38, 42,
    21, -73, -98, -87, 104, -107, 84, -111, -59, -33,
    -100, 60, 21, -51, 54, 58, 5, -89, -114, -71,
    120, -123, 68, -127, -43, -49, -116, 44, 5, -3,
    6, 10, 53, -105, -66, -119, 72, -75, 116, -79,
    -27, -1, -68, 28, 53, -19, 22, 26, 37, -121,
    -82, -103, 88, -91, 100, -95, -11, -17, -84, 12,
    37, 29, -26, -22, -43, 119, 94, 105, -88, 85,
    -108, 81, 5, 31, 92, -4, -43, 13, -10, -6,
    -59, 103, 78, 121, -72, 69, -124, 65, 21, 15,
    76, -20, -59, 61, -58, -54, -11, 87, 126, 73,
    -120, 117, -76, 113, 37, 63, 124, -36, -11, 45,
    -42, -38, -27, 71, 110, 89, -104, 101, -92, 97,
    53, 47, 108, -52, -27, 93, -90, -86, -107, 55,
    30, 41, -24, 21, -44, 17, 69, 95, 28, -68,
    -107, 77, -74, -70, -123, 39
  ].pack("C*")

  class Message
    # @return [Integer] the type of this message
    attr_accessor :type
    # @return [String] the password to attempt to authenticate with
    attr_accessor :password
    # @return [String] the optional message payload
    attr_accessor :payload
    # @return [Integer] the status of this message
    attr_accessor :status

    def initialize
      @payload = ''
      @type = 0
      @status = 0
      @password = ''
      @unknown1 = 1
      @unknown2 = ''
      @unknown3 = ''
      @unknown4 = ''
    end

    # Determines if this message has a successful status code
    #
    # @return [Boolean] true iff @status is 0, false otherwise
    def successful?
      @status == 0
    end

    # Get this Message as a String
    #
    # @return [String] the string representation of this Message
    def to_s
      with_checksum(Zlib.adler32(with_checksum(0)))
    end

    # Compares this Message and another Message for equality
    #
    # @param other [Message] the Message to compare
    # @return [Boolean] true iff the two messages are equal, false otherwise
    def ==(other)
      other.type == @type &&
        other.status == @status &&
        other.password == @password &&
        other.payload == @payload
    end

    # Decodes the provided data into a Message
    #
    # @param data [String] the data to parse as a Message
    # @param validate_checksum [Boolean] true to validate the message and
    #   payload checksums, false to not.  Defaults to true.
    # @return [Message] the decoded Message
    def self.decode(data, validate_checksum = true)
      data = data.dup
      fail "Incorrect ACPP message size #{data.size} -- must be 128" unless data.size == 128
      fail 'Unexpected header' unless 'acpp' == data.slice!(0, 4)
      _unknown1 = data.slice!(0, 4)
      read_message_checksum = data.slice!(0, 4).unpack('N').first
      read_payload_checksum = data.slice!(0, 4).unpack('N').first
      _read_payload_size = data.slice!(0, 4).unpack('N').first
      _unknown2 = data.slice!(0, 8)
      type = data.slice!(0, 4).unpack('N').first
      status = data.slice!(0, 4).unpack('N').first
      _unknown3 = data.slice!(0, 12)
      password = Rex::Encoding::Xor::Generic.encode(data.slice!(0, 32), XOR_KEY).first.strip
      _unknown4 = data.slice!(0, 48)
      payload = data
      m = new
      m.type = type
      m.password = password
      m.status = status
      m.payload = payload

      # we can now validate the checksums if desired
      if validate_checksum
        actual_message_checksum = Zlib.adler32(m.with_checksum(0))
        if actual_message_checksum != read_message_checksum
          fail "Invalid message checksum (expected #{read_message_checksum}, calculated #{actual_message_checksum})"
        end
        # I'm not sure this can ever happen -- if the payload checksum is wrong, then the
        # message checksum will also be wrong.  So, either I misunderstand the protocol
        # or having two checksums is useless
        actual_payload_checksum = Zlib.adler32(payload)
        if actual_payload_checksum != read_payload_checksum
          fail "Invalid payload checksum (expected #{read_payload_checksum}, calculated #{actual_payload_checksum})"
        end
      end
      m
    end

    def with_checksum(message_checksum)
      [
        'acpp',
        @unknown1,
        message_checksum,
        Zlib.adler32(@payload),
        @payload.size,
        @unknown2,
        @type,
        @status,
        @unknown3,
        Rex::Encoding::Xor::Generic.encode([@password].pack('a32').slice(0, 32), XOR_KEY).first,
        @unknown4,
        payload
      ].pack('a4NNNNa8NNa12a32a48a*')
    end
  end
end
end
end
