module Zip
  # Info-ZIP Additional timestamp field
  class ExtraField::UniversalTime < ExtraField::Generic
    HEADER_ID = 'UT'
    register_map

    def initialize(binstr = nil)
      @ctime = nil
      @mtime = nil
      @atime = nil
      @flag  = nil
      binstr && merge(binstr)
    end

    attr_accessor :atime, :ctime, :mtime, :flag

    def merge(binstr)
      return if binstr.empty?
      size, content = initial_parse(binstr)
      size || return
      @flag, mtime, atime, ctime = content.unpack('CVVV')
      mtime && @mtime ||= ::Zip::DOSTime.at(mtime)
      atime && @atime ||= ::Zip::DOSTime.at(atime)
      ctime && @ctime ||= ::Zip::DOSTime.at(ctime)
    end

    def ==(other)
      @mtime == other.mtime &&
        @atime == other.atime &&
        @ctime == other.ctime
    end

    def pack_for_local
      s = [@flag].pack('C')
      @flag & 1 != 0 && s << [@mtime.to_i].pack('V')
      @flag & 2 != 0 && s << [@atime.to_i].pack('V')
      @flag & 4 != 0 && s << [@ctime.to_i].pack('V')
      s
    end

    def pack_for_c_dir
      s = [@flag].pack('C')
      @flag & 1 == 1 && s << [@mtime.to_i].pack('V')
      s
    end
  end
end
