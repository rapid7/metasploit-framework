module Zip
  # Olf Info-ZIP Extra for UNIX uid/gid and file timestampes
  class ExtraField::OldUnix < ExtraField::Generic
    HEADER_ID = 'UX'
    register_map

    def initialize(binstr = nil)
      @uid = 0
      @gid = 0
      @atime = nil
      @mtime = nil
      binstr && merge(binstr)
    end

    attr_accessor :uid, :gid, :atime, :mtime

    def merge(binstr)
      return if binstr.empty?
      size, content = initial_parse(binstr)
      # size: 0 for central directory. 4 for local header
      return if !size || size == 0
      atime, mtime, uid, gid = content.unpack('VVvv')
      @uid ||= uid
      @gid ||= gid
      @atime ||= atime
      @mtime ||= mtime
    end

    def ==(other)
      @uid == other.uid &&
        @gid == other.gid &&
        @atime == other.atime &&
        @mtime == other.mtime
    end

    def pack_for_local
      [@atime, @mtime, @uid, @gid].pack('VVvv')
    end

    def pack_for_c_dir
      [@atime, @mtime].pack('VV')
    end
  end
end
