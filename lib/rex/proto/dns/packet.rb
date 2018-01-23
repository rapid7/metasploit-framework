# -*- coding: binary -*-

require 'net/dns'
require 'resolv'
require 'dnsruby'

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
  # @param packet [String, Net::DNS::Packet, Dnsruby::Message] Data to be validated
  #
  # @return [Dnsruby::Message]
  def self.validate(packet)
      self.encode_drb(self.encode_net(self.encode_res(packet)))
  end

  #
  # Sets header values to match packet content
  #
  # @param packet [String] Net::DNS::Packet, Resolv::DNS::Message,  Dnsruby::Message]
  #
  # @return [Dnsruby::Message]
  def self.recalc_headers(packet)
    packet = self.encode_drb(packet)
    {
      :qdcount= => :question,
      :ancount= => :answer,
      :nscount= => :authority,
      :arcount= => :additional
    }.each do |header,body|
      packet.header.send(header,packet.send(body).count)
    end

    return packet
  end

  #
  # Reads a packet into the Net::DNS::Packet format
  #
  # @param data [String, Net::DNS::Packet, Resolv::DNS::Message, Dnsruby::Message] Input data
  #
  # @return [Net::DNS::Packet]
  def self.encode_net(packet)
    return packet if packet.is_a?(Net::DNS::Packet)
    Net::DNS::Packet.parse(
      self.encode_raw(packet)
    )
  end

  # Reads a packet into the Resolv::DNS::Message format
  #
  # @param data [String, Net::DNS::Packet, Resolv::DNS::Message, Dnsruby::Message] Input data
  #
  # @return [Resolv::DNS::Message]
  def self.encode_res(packet)
    return packet if packet.is_a?(Resolv::DNS::Message)
    Resolv::DNS::Message.decode(
      self.encode_raw(packet)
    )
  end

  # Reads a packet into the Dnsruby::Message format
  #
  # @param data [String, Net::DNS::Packet, Resolv::DNS::Message, Dnsruby::Message] Input data
  #
  # @return [Dnsruby::Message]
  def self.encode_drb(packet)
    return packet if packet.is_a?(Dnsruby::Message)
    Dnsruby::Message.decode(
      self.encode_raw(packet)
    )
  end

  # Reads a packet into the raw String format
  #
  # @param data [String, Net::DNS::Packet, Resolv::DNS::Message, Dnsruby::Message] Input data
  #
  # @return [String]
  def self.encode_raw(packet)
    return packet unless packet.respond_to?(:encode) or packet.respond_to?(:data)
    (packet.respond_to?(:data) ? packet.data : packet.encode).force_encoding('binary')
  end

  #
  # Generates a request packet, taken from Net::DNS::Resolver
  #
  # @param subject [String] Subject name of question section
  # @param type [Fixnum] Type of DNS record to query
  # @param cls [Fixnum] Class of dns record to query
  # @param recurse [Fixnum] Recursive query or not
  #
  # @return [Dnsruby::Message] request packet
  def self.generate_request(subject, type = Dnsruby::Types::A, cls = Dnsruby::Classes::IN, recurse = 1)
    case subject
    when IPAddr
      name = subject.reverse
      type = Dnsruby::Types::PTR
    when /\d/ # Contains a number, try to see if it's an IP or IPv6 address
      begin
        name = IPAddr.new(subject).reverse
        type = Dnsruby::Types::PTR
      rescue ArgumentError
        name = subject if self.valid_hostname?(subject)
      end
    else
      name = subject if self.valid_hostname?(subject)
    end

    # Create the packet
    packet = Dnsruby::Message.new(name, type, cls)

    if packet.header.opcode == Dnsruby::OpCode::Query
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
  # @param authority [Array] Set of authority records to provide in the response
  # @param additional [Array] Set of additional records to provide in the response
  #
  # @return [Dnsruby::Message] Response packet
  def self.generate_response(request, answer = nil, authority = nil, additional = nil)
    packet = self.encode_drb(request)
    packet.answer = answer if answer
    packet.authority = authority if authority
    packet.additional = additional if additional
    packet = self.recalc_headers(packet)

    # Set error code for NXDomain or unset it if reprocessing a response
    if packet.header.ancount < 1
      packet.header.rcode = Dnsruby::RCode::NXDOMAIN
    else
      if packet.header.qr and packet.header.get_header_rcode.to_i == 3
        packet.header.rcode = Dnsruby::RCode::NOERROR
      end
    end
    # Set response bit last to allow reprocessing of responses
    packet.header.qr = true
    # Set recursion available bit if recursion desired
    packet.header.ra = true if packet.header.rd
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
