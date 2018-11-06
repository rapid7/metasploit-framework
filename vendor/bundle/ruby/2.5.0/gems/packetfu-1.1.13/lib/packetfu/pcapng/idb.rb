require 'stringio'

module PacketFu
  module PcapNG

    # Pcapng::IDB represents a Interface Description Block (IDB) of a pcapng file.
    #
    # == Pcapng::IDB Definition
    #   Int32   :type           Default: 0x00000001
    #   Int32   :block_len
    #   Int16   :link_type      Default: 1
    #   Int16   :reserved       Default: 0
    #   Int64   :snaplen        Default: 0 (no limit)
    #   String  :options
    #   Int32   :block_len2
    class IDB < Struct.new(:type, :block_len, :link_type, :reserved,
                           :snaplen, :options, :block_len2)
      include StructFu
      include Block
      attr_accessor :endian
      attr_accessor :section
      attr_accessor :packets

      MIN_SIZE     = 5*4

      # Option code for if_tsresol option
      OPTION_IF_TSRESOL = 9

      def initialize(args={})
        @endian = set_endianness(args[:endian] || :little)
        @packets = []
        @options_decoded = false
        init_fields(args)
        super(args[:type], args[:block_len], args[:link_type], args[:reserved],
              args[:snaplen], args[:options], args[:block_len2])
      end

      # Used by #initialize to set the initial fields
      def init_fields(args={})
        args[:type]  = @int32.new(args[:type] || PcapNG::IDB_TYPE.to_i)
        args[:block_len] = @int32.new(args[:block_len] || MIN_SIZE)
        args[:link_type] = @int16.new(args[:link_type] || 1)
        args[:reserved] = @int16.new(args[:reserved] || 0)
        args[:snaplen] = @int32.new(args[:snaplen] || 0)
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
        self[:link_type].read io.read(2)
        self[:reserved].read io.read(2)
        self[:snaplen].read io.read(4)
        self[:options].read io.read(self[:block_len].to_i - MIN_SIZE)
        self[:block_len2].read io.read(4)

        unless self[:block_len].to_i == self[:block_len2].to_i
          raise InvalidFileError, 'Incoherency in Interface Description Block'
        end
      
        self
      end
      
      # Add a xPB to this section
      def <<(xpb)
        @packets << xpb
      end

      # Give timestamp resolution for this interface
      def ts_resol(force=false)
        if @options_decoded and not force
          @ts_resol
        else
          packstr = (@endian == :little) ? 'v' : 'n'
          idx = 0
          options = self[:options]
          opt_code = opt_len = 0

          while idx < options.length do
            opt_code, opt_len = options[idx, 4].unpack("#{packstr}2")
            if opt_code == OPTION_IF_TSRESOL and opt_len == 1
              tsresol = options[idx+4, 1].unpack('C').first
              if tsresol & 0x80 == 0
                @ts_resol = 10 ** -tsresol
              else
                @ts_resol = 2 ** -(tsresol & 0x7f)
              end

              @options_decoded = true
              return @ts_resol
            else
              idx += 4 + opt_len
            end
          end

          @options_decoded = true
          @ts_resol = 1E-6  # default value
        end
      end

      # Return the object as a String
      def to_s
        pad_field :options
        recalc_block_len
        to_a.map(&:to_s).join + @packets.map(&:to_s).join
      end

    end

  end
end
