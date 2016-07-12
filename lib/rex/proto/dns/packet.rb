require 'net/dns'
require 'resolv'

module Rex
module Proto
module DNS

module Packet

  #
  # Checks string to ensure it can be used as a valid hostname
  #
  # @param subject [String] Subject name to check
  #
  # @return [TrueClass,FalseClass] Disposition on name match
  def self.valid_hostname?(subject = '')
    !subject.match(Rex::Proto::DNS::Constants::MATCH_HOSTNAME).nil?
  end

  #
  # Reconstructs a packet with both standard DNS libraries
  # Ensures that headers match the payload
  #
  # @param packet [String, Net::DNS::Packet] Data to be validated
  #
  # @return [Net::DNS::Packet]
  def self.validate(packet)
      self.encode_net(self.encode_res(self.encode_raw(packet)))
  end

  #
  # Reads a packet into the Net::DNS::Packet format
  #
  # @param data [String, Net::DNS::Packet, Resolv::DNS::Message] Input data
  #
  # @return [Net::DNS::Packet]
  def self.encode_net(packet)
    return packet if packet.respond_to?(:data)
    Net::DNS::Packet.parse(
      packet.respond_to?(:encode) ? packet.encode : packet
    )
  end

  # Reads a packet into the Resolv::DNS::Message format
  #
  # @param data [String, Net::DNS::Packet, Resolv::DNS::Message] Input data
  #
  # @return [Resolv::DNS::Message]
  def self.encode_res(packet)
    return packet if packet.respond_to?(:encode)
    Resolv::DNS::Message.decode(
      packet.respond_to?(:data) ? packet.data : packet
    )
  end

  # Reads a packet into the raw String format
  #
  # @param data [String, Net::DNS::Packet, Resolv::DNS::Message] Input data
  #
  # @return [Resolv::DNS::Message]
  def self.encode_raw(packet)
    return packet unless packet.respond_to?(:encode) or packet.respond_to?(:data)
    packet.respond_to?(:data) ? packet.data : packet.encode
  end

  #
  # Generates a request packet, taken from Net::DNS::Resolver
  #
  # @param subject [String] Subject name of question section
  # @param type [Fixnum] Type of DNS record to query
  # @param cls [Fixnum] Class of dns record to query
  # @param recurse [Fixnum] Recursive query or not
  #
  # @return [Net::DNS::Packet] request packet
  def self.generate_request(subject, type = Net::DNS::A, cls = Net::DNS::IN, recurse = 1)
    case subject
    when IPAddr
      name = subject.reverse
      type = Net::DNS::PTR
    when /\d/ # Contains a number, try to see if it's an IP or IPv6 address
      begin
        name = IPAddr.new(subject).reverse
        type = Net::DNS::PTR
      rescue ArgumentError
        name = subject if self.valid_hostname?(subject)
      end
    else
      name = subject if self.valid_hostname?(subject)
    end

    # Create the packet
    packet = Net::DNS::Packet.new(name,type,cls)

    if packet.query?
      packet.header.recursive = recurse
    end

    # DNSSEC and TSIG stuff to be inserted here

    return packet
  end

  #
  # Generates a response packet for an existing request
  #
  # @param request [String] Net::DNS::Packet, Resolv::DNS::Message] Original request
  # @param answer [Array] Set of answers to provide in the response
  #
  # @return [Net::DNS::Packet] Response packet
  def self.generate_response(request, answer = nil)
    packet = self.encode_net(request)
    packet.answer = answer unless answer.nil?
    # Set answer count header section
    packet.header.anCount = packet.answer.count
    # Set error code for NXDomain or unset it if reprocessing a response
    if packet.header.anCount < 1
      packet.header.rCode = 3
    else
      if packet.header.response? and packet.header.rCode.code == 3
        packet.header.rCode = 0
      end
    end
    # Set response bit last to allow reprocessing of responses
    packet.header.qr = 1
    # Set recursion available bit if recursion desired
    packet.header.ra = 1 if packet.header.recursive?
    return packet
  end

  module Raw

    #
    # Convert data to little endian unsigned short
    #
    # @param data [Fixnum, Float, Array] Input for conversion
    #
    # @return [String] Raw output
    def self.to_short_le(data)
      [data].flatten.pack('S*')
    end

    #
    # Convert data from little endian unsigned short
    #
    # @param data [String] Input for conversion
    #
    # @return [Array] Integer array output
    def self.from_short_le(data)
      data.unpack('S*')
    end

    #
    # Convert data to little endian unsigned int
    #
    # @param data [Fixnum, Float, Array] Input for conversion
    #
    # @return [String] Raw output
    def self.to_int_le(data)
      [data].flatten.pack('I*')
    end

    #
    # Convert data from little endian unsigned int
    #
    # @param data [String] Input for conversion
    #
    # @return [Array] Integer array output
    def self.from_int_le(data)
      data.unpack('I*')
    end

    #
    # Convert data to little endian unsigned long
    #
    # @param data [Fixnum, Float, Array] Input for conversion
    #
    # @return [String] Raw output
    def self.to_long_le(data)
      [data].flatten.pack('L*')
    end

    #
    # Convert data from little endian unsigned long
    #
    # @param data [String] Input for conversion
    #
    # @return [Array] Integer array output
    def self.from_long_le(data)
      data.unpack('L*')
    end

    #
    # Convert data to big endian unsigned short
    #
    # @param data [Fixnum, Float, Array] Input for conversion
    #
    # @return [String] Raw output
    def self.to_short_be(data)
      [data].flatten.pack('S>*')
    end

    #
    # Convert data from big endian unsigned short
    #
    # @param data [String] Input for conversion
    #
    # @return [Array] Integer array output
    def self.from_short_be(data)
      data.unpack('S>*')
    end

    #
    # Convert data to big endian unsigned int
    #
    # @param data [Fixnum, Float, Array] Input for conversion
    #
    # @return [String] Raw output
    def self.to_int_be(data)
      [data].flatten.pack('I>*')
    end

    #
    # Convert data from big endian unsigned int
    #
    # @param data [String] Input for conversion
    #
    # @return [Array] Integer array output
    def self.from_int_be(data)
      data.unpack('I>*')
    end

    #
    # Convert data to big endian unsigned long
    #
    # @param data [Fixnum, Float, Array] Input for conversion
    #
    # @return [String] Raw output
    def self.to_long_be(data)
      [data].flatten.pack('L>*')
    end

    #
    # Convert data from big endian unsigned long
    #
    # @param data [String] Input for conversion
    #
    # @return [Array] Integer array output
    def self.from_long_be(data)
      data.unpack('L>*')
    end

    #
    # Returns request ID from raw packet skipping parsing
    #
    # @param data [String] Request data
    #
    # @return [Fixnum] Request ID
    def self.request_id(data)
      self.from_short_be(data[0..1])[0]
    end

    #
    # Returns request length from raw packet skipping parsing
    #
    # @param data [String] Request data
    #
    # @return [Fixnum] Request Length
    def self.request_length(data)
      self.from_short_le(data[0..2])[0]
    end
  end
end

end
end
end
