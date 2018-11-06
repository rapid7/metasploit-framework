module Zip
  # PKWARE NTFS Extra Field (0x000a)
  # Only Tag 0x0001 is supported
  class ExtraField::NTFS < ExtraField::Generic
    HEADER_ID = [0x000A].pack('v')
    register_map

    WINDOWS_TICK = 10_000_000.0
    SEC_TO_UNIX_EPOCH = 11_644_473_600

    def initialize(binstr = nil)
      @ctime = nil
      @mtime = nil
      @atime = nil
      binstr && merge(binstr)
    end

    attr_accessor :atime, :ctime, :mtime

    def merge(binstr)
      return if binstr.empty?
      size, content = initial_parse(binstr)
      (size && content) || return

      content = content[4..-1]
      tags = parse_tags(content)

      tag1 = tags[1]
      return unless tag1
      ntfs_mtime, ntfs_atime, ntfs_ctime = tag1.unpack('Q<Q<Q<')
      ntfs_mtime && @mtime ||= from_ntfs_time(ntfs_mtime)
      ntfs_atime && @atime ||= from_ntfs_time(ntfs_atime)
      ntfs_ctime && @ctime ||= from_ntfs_time(ntfs_ctime)
    end

    def ==(other)
      @mtime == other.mtime &&
        @atime == other.atime &&
        @ctime == other.ctime
    end

    # Info-ZIP note states this extra field is stored at local header
    def pack_for_local
      pack_for_c_dir
    end

    # But 7-zip for Windows only stores at central dir
    def pack_for_c_dir
      # reserved 0 and tag 1
      s = [0, 1].pack('Vv')

      tag1 = ''.force_encoding(Encoding::BINARY)
      if @mtime
        tag1 << [to_ntfs_time(@mtime)].pack('Q<')
        if @atime
          tag1 << [to_ntfs_time(@atime)].pack('Q<')
          tag1 << [to_ntfs_time(@ctime)].pack('Q<') if @ctime
        end
      end
      s << [tag1.bytesize].pack('v') << tag1
      s
    end

    private

    def parse_tags(content)
      return {} if content.nil?
      tags = {}
      i = 0
      while i < content.bytesize
        tag, size = content[i, 4].unpack('vv')
        i += 4
        break unless tag && size
        value = content[i, size]
        i += size
        tags[tag] = value
      end

      tags
    end

    def from_ntfs_time(ntfs_time)
      ::Zip::DOSTime.at(ntfs_time / WINDOWS_TICK - SEC_TO_UNIX_EPOCH)
    end

    def to_ntfs_time(time)
      ((time.to_f + SEC_TO_UNIX_EPOCH) * WINDOWS_TICK).to_i
    end
  end
end
