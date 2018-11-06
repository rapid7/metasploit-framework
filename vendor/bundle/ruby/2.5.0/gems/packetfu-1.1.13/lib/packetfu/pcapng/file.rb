require_relative 'shb'

module PacketFu
  module PcapNG

    # PcapNG::File is a complete Pcap-NG file handler.
    class File
      attr_accessor :sections

      def initialize
        @sections = []
      end

      # Read a string to populate the object. Note that this appends new blocks to
      # the Pcapng::File object.
      def read(str)
        PacketFu.force_binary(str)
        io = StringIO.new(str)
        parse_section(io)
        self
      end

      # Clear the contents of the Pcapng::File prior to reading in a new string.
      # This string should contain a Section Header Block and an Interface Description
      # Block to create a conform pcapng file.
      def read!(str)
        clear
        PacketFu.force_binary(str)
        read(str)
      end

      # Read a given file and analyze it.
      # If given a block, it will yield PcapNG::EPB or PcapNG::SPB objects.
      # This is the only way to get packet timestamps.
      def readfile(fname, &blk)
        unless ::File.readable?(fname)
          raise ArgumentError, "cannot read file #{fname}"
        end

        ::File.open(fname, 'rb') do |f|
          while !f.eof? do
            parse_section(f)
          end
        end

        if blk
          count = 0
          @sections.each do |section|
            section.interfaces.each do |intf|
              intf.packets.each { |pkt| count += 1; yield pkt }
            end
          end
          count
        end
      end

      # Give an array of parsed packets (raw data from packets).
      # If a block is given, yield raw packet data from the given file.
      def read_packet_bytes(fname, &blk)
        count = 0
        packets = [] unless blk

        readfile(fname) do |packet|
          if blk
            count += 1
            yield packet.data.to_s
          else
            packets << packet.data.to_s
          end
        end

        blk ? count : packets
      end

      # Return an array of parsed packets.
      # If a block is given, yield parsed packets from the given file.
      def read_packets(fname, &blk)
        count = 0
        packets = [] unless blk

        read_packet_bytes(fname) do |packet|
          if blk
            count += 1
            yield Packet.parse(packet)
          else
            packets << Packet.parse(packet)
          end
        end

        blk ? count : packets
      end

      # Return the object as a String
      def to_s
        @sections.map { |section| section.to_s }.join
      end

      # Clear the contents of the Pcapng::File.
      def clear
        @sections.clear
      end

      # #file_to_array translates a Pcap-NG file into an array of packets.
      # Note that this strips out timestamps -- if you'd like to retain
      # timestamps and other pcapng file information, you will want to
      # use #read instead.
      #
      # Valid arguments are:
      #  * :filename           If given, object is cleared and filename is analyzed
      #                        before generating array. Else, array is generated
      #                        from self.
      #  * :keep_timestamps    If true, generates an array of hashes, each one with
      #                        timestamp as key and packet as value. There is one hash
      #                        per packet.
      def file_to_array(args={})
        filename = args[:filename] || args[:file]
        if filename
          clear
          readfile filename
        end

        ary = []
        @sections.each do |section|
          section.interfaces.each do |itf|
            if args[:keep_timestamps] || args[:keep_ts]
              ary.concat itf.packets.map { |pkt| { pkt.timestamp => pkt.data.to_s } }
            else
              ary.concat itf.packets.map { |pkt| pkt.data.to_s}
            end
          end
        end
        ary
      end

      # Writes the Pcapng::File to a file. Takes the following arguments:
      #   :filename # The file to write to.
      #   :append   # If set to true, the packets are appended to the file, rather
      #             # than overwriting.
      def to_file(args={})
        filename = args[:filename] || args[:file]
        unless (!filename.nil? || filename.kind_of?(String))
          raise ArgumentError, "Need a :filename for #{self.class}"
        end

        append = args[:append]
        mode = ''
        if append and ::File.exists? filename
          mode = 'ab'
        else
          mode = 'wb'
        end
        ::File.open(filename,mode) {|f| f.write(self.to_s)}
        [filename, self.to_s.size]
      end

      alias_method :to_f, :to_file

      # Shorthand method for writing to a file. Can take either :file => 'name.pcapng'
      # or simply 'name.pcapng'
      def write(filename='out.pcapng')
        if filename.kind_of?(Hash)
          f = filename[:filename] || filename[:file] || 'out.pcapng'
        else
          f = filename.to_s
        end
        self.to_file(:filename => f.to_s, :append => false)
      end

      # Shorthand method for appendong to a file. Can take either
      # :file => 'name.pcapng' or simply 'name.pcapng'
      def append(filename='out.pcapng')
        if filename.kind_of?(Hash)
          f = filename[:filename] || filename[:file] || 'out.pcapng'
        else
          f = filename.to_s
        end
        self.to_file(:filename => f.to_s, :append => true)
      end

      # Takes an array of packets  or a Hash.
      #
      # Array: as generated by file_to_array or Array of Packet objects.
      #        update Pcapng::File object without writing file on disk
      # Hash: take packets from args and write them to a file. Valid arguments are:
      #   :filename   # do not write file on disk if not given
      #   :array      # Can either be an array of packet data, or a hash-value pair
      #               # of timestamp => data.
      #   :timestamp  # Sets an initial timestamp (Time object)
      #   :ts_inc     # Sets the increment between timestamps. Defaults to 1 second.
      #   :append     # If true, then the packets are appended to the end of a file.
      def array_to_file(args={})
        case args
        when Hash
          filename = args[:filename] || args[:file]
          ary = args[:array] || args[:arr]
          unless ary.kind_of? Array
            raise ArgumentError, ':array parameter needs to be an array'
          end
          ts = args[:timestamp] || args[:ts] || Time.now
          ts_inc = args[:ts_inc] || 1
          append = !!args[:append]
        when Array
          ary = args
          ts = Time.now
          ts_inc = 1
          filename = nil
          append = false
        else
          raise ArgumentError, 'unknown argument. Need either a Hash or Array'
        end

        section = SHB.new
        @sections << section
        itf = IDB.new(:endian => section.endian)
        classify_block section, itf

        ary.each_with_index do |pkt, i|
          case pkt
          when Hash
            this_ts = pkt.keys.first.to_i
            this_cap_len = pkt.values.first.to_s.size
            this_data = pkt.values.first.to_s
          else
            this_ts = (ts + ts_inc * i).to_i
            this_cap_len = pkt.to_s.size
            this_data = pkt.to_s
          end
          this_ts = (this_ts / itf.ts_resol).to_i
          this_tsh = this_ts >> 32
          this_tsl = this_ts & 0xffffffff
          this_pkt = EPB.new(:endian       => section.endian,
                             :interface_id => 0,
                             :tsh          => this_tsh,
                             :tsl          => this_tsl,
                             :cap_len      => this_cap_len,
                             :orig_len     => this_cap_len,
                             :data         => this_data)
          classify_block section, this_pkt
        end

        if filename
          self.to_f(:filename => filename, :append => append)
        else
          self
        end
      end


      private

      def parse_section(io)
        shb = SHB.new
        type = StructFu::Int32.new(0, shb.endian).read(io.read(4))
        io.seek(-4, IO::SEEK_CUR)
        shb = parse(type, io, shb)
        raise InvalidFileError, 'no Section header found' unless shb.is_a?(SHB)

        if shb.section_len.to_i != 0xffffffffffffffff
          # Section length is defined
          section = StringIO.new(io.read(shb.section_len.to_i))
          while !section.eof? do
            shb = @sections.last
            type = StructFu::Int32.new(0, shb.endian).read(section.read(4))
            section.seek(-4, IO::SEEK_CUR)
            block = parse(type, section, shb)
          end
        else
          # section length is undefined
          while !io.eof?
            shb = @sections.last
            type = StructFu::Int32.new(0, shb.endian).read(io.read(4))
            io.seek(-4, IO::SEEK_CUR)
            block = parse(type, io, shb)
          end
        end
      end

      def parse(type, io, shb)
        types = PcapNG.constants(false).select { |c| c.to_s =~ /_TYPE/ }.
          map { |c| [PcapNG.const_get(c).to_i, c] }
        types = Hash[types]

        if types.has_key?(type.to_i)
          klass = PcapNG.const_get(types[type.to_i].to_s.gsub(/_TYPE/, '').to_sym)
          block = klass.new(endian: shb.endian)
        else
          block = UnknownBlock.new(endian: shb.endian)
        end

        classify_block shb, block
        block.read(io)
      end

      def classify_block(shb, block)
        case block
        when SHB
          @sections << block
        when IDB
          shb << block
          block.section = shb
        when EPB
          shb.interfaces[block.interface_id.to_i] << block
          block.interface = shb.interfaces[block.interface_id.to_i]
        when SPB
          shb.interfaces[0] << block
          block.interface = shb.interfaces[0]
        else
          shb.unknown_blocks << block
          block.section = shb
        end
      end

    end

  end
end
