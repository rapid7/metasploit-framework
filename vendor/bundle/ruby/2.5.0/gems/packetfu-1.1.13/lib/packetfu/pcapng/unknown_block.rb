require 'stringio'

module PacketFu
  module PcapNG

    # Pcapng::UnknownBlock is used to handle unsupported blocks of a pcapng file.
    class UnknownBlock < Struct.new(:type, :block_len, :body, :block_len2)
      include StructFu
      include Block
      attr_accessor :endian
      attr_accessor :section

      MIN_SIZE     = 12

      def initialize(args={})
        @endian = set_endianness(args[:endian] || :little)
        init_fields(args)
        super(args[:type], args[:block_len], args[:body], args[:block_len2])
      end

      # Used by #initialize to set the initial fields
      def init_fields(args={})
        args[:type]  = @int32.new(args[:type] || 0)
        args[:block_len] = @int32.new(args[:block_len] || MIN_SIZE)
        args[:body] = StructFu::String.new(args[:body] || '')
        args[:block_len2] = @int32.new(args[:block_len2] || MIN_SIZE)
        args
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
        self[:body].read io.read(self[:block_len].to_i - MIN_SIZE)
        self[:block_len2].read io.read(4)
        
        unless self[:block_len].to_i == self[:block_len2].to_i
          raise InvalidFileError, 'Incoherency in Header Block'
        end

        self
      end

      # Return the object as a String
      def to_s
        pad_field :body
        recalc_block_len
        to_a.map(&:to_s).join
      end

    end

  end
end
