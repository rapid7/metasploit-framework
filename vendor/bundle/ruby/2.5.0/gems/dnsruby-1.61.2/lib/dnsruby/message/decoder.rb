module Dnsruby

# This class decodes a binary string containing the raw bytes of the message
# as in coming over the wire from a nameserver, and parses it into a
# Dnsruby::Message.
class MessageDecoder #:nodoc: all

  # Keeps a running @index containing the current position (like a cursor)
  # into the binary string.  In general 'get_' methods will position @index
  # to follow the data they have read.

  attr_reader :data, :index

  # Creates an instance of the decoder, optionally with code block
  # to be executed with the instance as its parameter.
  def initialize(data)
    @data = data
    @index = 0
    @limit = data.length
    yield self if block_given?
  end

  # Has bytes remaining in the binary string to be parsed?
  def has_remaining?
    @limit > @index
  end

  # Asserts that the specified position is a valid position in the buffer.
  # If not, raises a DecodeError.  If so, does nothing.
  def assert_buffer_position_valid(end_position)
    unless (0..@limit).include?(end_position)
      raise DecodeError.new("requested position of #{end_position} must be between 0 and buffer size (#{@limit}).")
    end
  end

  # Gets the byte value at the specified position
  def get_byte_at(position)
    assert_buffer_position_valid(position)
    return nil if @data[position].nil?
    @data[position].getbyte(0)
  end

  # Gets a 16-bit length field from the binary string and yields to the block.
  # This will be the length of the next item to parse in the binary string.
  # Returns the object returned from that block.
  #
  # When this method returns, @index will point to the byte after the
  # 16-bit length field.
  def get_length16
    len, = self.get_unpack('n')
    save_limit = @limit
    @limit = @index + len
    parsed_data = yield(len)
    if @index < @limit
      message = "Junk exists; limit = #{@limit}, index = #{@index}"
      raise DecodeError.new(message)
    end
    assert_buffer_position_valid(@index)
    @limit = save_limit
    parsed_data
  end

  # Returns the specified number of bytes from the binary string.
  # Length defaults to the remaining (not yet processed) size of the string.
  def get_bytes(len = @limit - @index)
    bytes = @data[@index, len]
    @index += len
    bytes
  end

  # Calls String.unpack to get numbers as specified in the template string.
  def get_unpack(template)
    len = 0

    template.bytes.each do |byte|
      case byte.chr
        when 'c', 'C', 'h', 'H'
          len += 1
        when 'n'
          len += 2
        when 'N'
          len += 4
        when '*'
          len = @limit - @index
        else
          raise StandardError.new("unsupported template: '#{byte.chr}' in '#{template}'")
      end
    end

    assert_buffer_position_valid(@index + len)
    number_array = @data.unpack("@#{@index}#{template}")
    @index += len
    number_array
  end

  # Gets a string whose 1-byte length is at @index, and the string starting at @index + 1.
  def get_string
    len = get_byte_at(@index) || 0
    assert_buffer_position_valid(@index + 1 + len)
    data_item = @data[@index + 1, len]
    @index += 1 + len
    data_item
  end

  # Gets all strings from @index to the end of the binary string.
  def get_string_list
    strings = []
    strings << get_string while has_remaining?
    strings
  end

  # Gets a Name from the current @index position.
  def get_name
    Name.new(get_labels)
  end

  # Returns labels starting at @index.
  def get_labels(limit = nil)
    limit = @index if limit.nil? || (@index < limit)
    labels = []
    while true
      temp = get_byte_at(@index)
      case temp
        when 0
          @index += 1
          return labels
        when 192..255
          idx = get_unpack('n')[0] & 0x3fff
          if limit <= idx
            raise DecodeError.new('non-backward name pointer')
          end
          save_index = @index
          @index = idx
          labels += self.get_labels(limit)
          @index = save_index
          return labels
        when nil
          return labels
        else
          labels << self.get_label
      end
    end
    labels
  end

  # Gets a single label.
  def get_label
    begin
      Name::Label.new(get_string)
    rescue ResolvError => e
      raise DecodeError.new(e) # Turn it into something more suitable
    end
  end

  # Gets a question record.
  def get_question
    name = self.get_name
    type, klass = self.get_unpack('nn')
    klass = Classes.new(klass)
    Question.new(name, type, klass)
  end

  # Gets a resource record.
  def get_rr
    name = get_name
    type, klass, ttl = get_unpack('nnN')
    klass = Classes.new(klass)
    typeclass = RR.get_class(type, klass)
    #  @TODO@ Trap decode errors here, and somehow mark the record as bad.
    #  Need some way to represent raw data only
    record = get_length16 { typeclass.decode_rdata(self) }
    record.name = name
    record.ttl = ttl
    record.type = type
    record.klass = klass
    record
  end
end
end
