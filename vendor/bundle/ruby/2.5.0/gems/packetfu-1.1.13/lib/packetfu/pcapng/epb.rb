require 'stringio'

module PacketFu
  module PcapNG

    # Pcapng::EPB represents a Extended Packet Block (EPB) of a pcapng file.
    #
    # == Pcapng::EPB Definition
    #   Int32   :type           Default: 0x00000006
    #   Int32   :block_len
    #   Int32   :interface_id
    #   Int32   :tsh (timestamp high)
    #   Int32   :tsl (timestamp low)
    #   Int32   :cap_len
    #   Int32   :orig_len
    #   String  :data
    #   String  :options
    #   Int32   :block_len2
    class EPB < Struct.new(:type, :block_len, :interface_id, :tsh, :tsl,
                           :cap_len, :orig_len, :data, :options, :block_len2)
      include StructFu
      include Block
      attr_accessor :endian
      attr_accessor :interface

      MIN_SIZE     = 8*4

      def initialize(args={})
        @endian = set_endianness(args[:endian] || :little)
        init_fields(args)
        super(args[:type], args[:block_len], args[:interface_id], args[:tsh],
              args[:tsl], args[:cap_len], args[:orig_len], args[:data],
              args[:options], args[:block_len2])
      end

      # Used by #initialize to set the initial fields
      def init_fields(args={})
        args[:type]  = @int32.new(args[:type] || PcapNG::EPB_TYPE.to_i)
        args[:block_len] = @int32.new(args[:block_len] || MIN_SIZE)
        args[:interface_id] = @int32.new(args[:interface_id] || 0)
        args[:tsh] = @int32.new(args[:tsh] || 0)
        args[:tsl] = @int32.new(args[:tsl] || 0)
        args[:cap_len] = @int32.new(args[:cap_len] || 0)
        args[:orig_len] = @int32.new(args[:orig_len] || 0)
        args[:data] = StructFu::String.new(args[:data] || '')
        args[:options] = StructFu::String.new(args[:options] || '')
        args[:block_len2] = @int32.new(args[:block_len2] || MIN_SIZE)
        args
      end

      def has_options?
        self[:options].size > 0
      end

      # Reads a String or a IO to populate the object
      def read(str_or_io)
        if str_or_io.respond_to? :read
          io = str_or_io
        else
          io = StringIO.new(force_binary(str_or_io.to_s))
        end
        return self if io.eof?

        self[:type].read io.read(4)
        self[:block_len].read io.read(4)
        self[:interface_id].read io.read(4)
        self[:tsh].read io.read(4)
        self[:tsl].read io.read(4)
        self[:cap_len].read io.read(4)
        self[:orig_len].read io.read(4)
        self[:data].read io.read(self[:cap_len].to_i)
        data_pad_len = (4 - (self[:cap_len].to_i % 4)) % 4
        io.read data_pad_len
        options_len = self[:block_len].to_i - self[:cap_len].to_i - data_pad_len
        options_len -= MIN_SIZE
        self[:options].read io.read(options_len)
        self[:block_len2].read io.read(4)

        unless self[:block_len].to_i == self[:block_len2].to_i
          raise InvalidFileError, 'Incoherency in Extended Packet Block'
        end
      
        self
      end

      # Return timestamp as a Time object
      def timestamp
        Time.at((self[:tsh].to_i << 32 | self[:tsl].to_i) * ts_resol)
      end

      # Return the object as a String
      def to_s
        pad_field :data, :options
        recalc_block_len
        to_a.map(&:to_s).join
      end


      private

      def ts_resol
        if @interface.nil?
          1E-6
        else
          @interface.ts_resol
        end
      end

    end

  end
end
