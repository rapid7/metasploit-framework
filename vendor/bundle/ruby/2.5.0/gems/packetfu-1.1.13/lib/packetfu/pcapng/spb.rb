require 'stringio'

module PacketFu
  module PcapNG

    # Pcapng::SPB represents a Section Simple Packet Block (SPB) of a pcapng file.
    #
    # == Pcapng::SPB Definition
    #   Int32   :type           Default: 0x00000003
    #   Int32   :block_len
    #   Int32   :orig_len
    #   String  :data
    #   Int32   :block_len2
    class SPB < Struct.new(:type, :block_len, :orig_len, :data, :block_len2)
      include StructFu
      include Block
      attr_accessor :endian
      attr_accessor :interface

      MIN_SIZE     = 4*4

      def initialize(args={})
        @endian = set_endianness(args[:endian] || :little)
        init_fields(args)
        super(args[:type], args[:block_len], args[:orig_len], args[:data],
              args[:block_len2])
      end

      # Used by #initialize to set the initial fields
      def init_fields(args={})
        args[:type]  = @int32.new(args[:type] || PcapNG::SPB_TYPE.to_i)
        args[:block_len] = @int32.new(args[:block_len] || MIN_SIZE)
        args[:orig_len] = @int32.new(args[:orig_len] || 0)
        args[:data] = StructFu::String.new(args[:data] || '')
        args[:block_len2] = @int32.new(args[:block_len2] || MIN_SIZE)
        args
      end

      def has_options?
        false
      end

      def read(str_or_io)
        if str_or_io.respond_to? :read
          io = str_or_io
        else
          io = StringIO.new(force_binary(str_or_io.to_s))
        end
        return self if io.eof?

        self[:type].read io.read(4)
        self[:block_len].read io.read(4)
        self[:orig_len].read io.read(4)
        # Take care of IDB snaplen
        # CAUTION: snaplen == 0 -> no capture limit
        if interface and interface.snaplen.to_i > 0
          data_len = [self[:orig_len].to_i, interface.snaplen.to_i].min
        else
          data_len = self[:orig_len].to_i
        end
        data_pad_len = (4 - (data_len % 4)) % 4
        self[:data].read io.read(data_len)
        io.read data_pad_len
        self[:block_len2].read io.read(4)

        unless self[:block_len].to_i == self[:block_len2].to_i
          raise InvalidFileError, 'Incoherency in Simple Packet Block'
        end

        self
      end

      # Return the object as a String
      def to_s
        pad_field :data
        recalc_block_len
        to_a.map(&:to_s).join
      end

    end

  end
end
