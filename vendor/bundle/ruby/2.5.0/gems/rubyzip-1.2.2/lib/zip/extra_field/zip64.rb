module Zip
  # Info-ZIP Extra for Zip64 size
  class ExtraField::Zip64 < ExtraField::Generic
    attr_accessor :original_size, :compressed_size, :relative_header_offset, :disk_start_number
    HEADER_ID = ['0100'].pack('H*')
    register_map

    def initialize(binstr = nil)
      # unparsed binary; we don't actually know what this contains
      # without looking for FFs in the associated file header
      # call parse after initializing with a binary string
      @content = nil
      @original_size          = nil
      @compressed_size        = nil
      @relative_header_offset = nil
      @disk_start_number      = nil
      binstr && merge(binstr)
    end

    def ==(other)
      other.original_size == @original_size &&
        other.compressed_size == @compressed_size &&
        other.relative_header_offset == @relative_header_offset &&
        other.disk_start_number == @disk_start_number
    end

    def merge(binstr)
      return if binstr.empty?
      _, @content = initial_parse(binstr)
    end

    # pass the values from the base entry (if applicable)
    # wider values are only present in the extra field for base values set to all FFs
    # returns the final values for the four attributes (from the base or zip64 extra record)
    def parse(original_size, compressed_size, relative_header_offset = nil, disk_start_number = nil)
      @original_size = extract(8, 'Q<') if original_size == 0xFFFFFFFF
      @compressed_size = extract(8, 'Q<') if compressed_size == 0xFFFFFFFF
      @relative_header_offset = extract(8, 'Q<') if relative_header_offset && relative_header_offset == 0xFFFFFFFF
      @disk_start_number = extract(4, 'V') if disk_start_number && disk_start_number == 0xFFFF
      @content = nil
      [@original_size || original_size,
       @compressed_size || compressed_size,
       @relative_header_offset || relative_header_offset,
       @disk_start_number || disk_start_number]
    end

    def extract(size, format)
      @content.slice!(0, size).unpack(format)[0]
    end
    private :extract

    def pack_for_local
      # local header entries must contain original size and compressed size; other fields do not apply
      return '' unless @original_size && @compressed_size
      [@original_size, @compressed_size].pack('Q<Q<')
    end

    def pack_for_c_dir
      # central directory entries contain only fields that didn't fit in the main entry part
      packed = ''.force_encoding('BINARY')
      packed << [@original_size].pack('Q<') if @original_size
      packed << [@compressed_size].pack('Q<') if @compressed_size
      packed << [@relative_header_offset].pack('Q<') if @relative_header_offset
      packed << [@disk_start_number].pack('V') if @disk_start_number
      packed
    end
  end
end
