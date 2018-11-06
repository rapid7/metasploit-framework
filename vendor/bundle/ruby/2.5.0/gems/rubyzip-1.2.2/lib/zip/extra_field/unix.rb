module Zip
  # Info-ZIP Extra for UNIX uid/gid
  class ExtraField::IUnix < ExtraField::Generic
    HEADER_ID = 'Ux'
    register_map

    def initialize(binstr = nil)
      @uid = 0
      @gid = 0
      binstr && merge(binstr)
    end

    attr_accessor :uid, :gid

    def merge(binstr)
      return if binstr.empty?
      size, content = initial_parse(binstr)
      # size: 0 for central directory. 4 for local header
      return if !size || size == 0
      uid, gid = content.unpack('vv')
      @uid ||= uid
      @gid ||= gid
    end

    def ==(other)
      @uid == other.uid && @gid == other.gid
    end

    def pack_for_local
      [@uid, @gid].pack('vv')
    end

    def pack_for_c_dir
      ''
    end
  end
end
