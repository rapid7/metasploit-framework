# -*- coding: binary -*-
#
# This is a Ruby port of the Python manifest parsing code posted to:
# 	http://stackoverflow.com/questions/3085153/how-to-parse-the-manifest-mbdb-file-in-an-ios-4-0-itunes-backup/3130860#3130860
#

module Rex
module Parser
class AppleBackupManifestDB

  attr_accessor :entry_offsets
  attr_accessor :entries
  attr_accessor :mbdb, :mbdx
  attr_accessor :mbdb_data, :mbdx_data
  attr_accessor :mbdb_offset, :mbdx_offset

  def initialize(mbdb_data, mbdx_data)
    self.entries = {}
    self.entry_offsets = {}
    self.mbdb_data = mbdb_data
    self.mbdx_data = mbdx_data
    parse_mbdb
    parse_mbdx
  end

  def self.from_files(mbdb_file, mbdx_file)
    mbdb_data = ""
    ::File.open(mbdb_file, "rb") {|fd| mbdb_data = fd.read(fd.stat.size) }
    mbdx_data = ""
    ::File.open(mbdx_file, "rb") {|fd| mbdx_data = fd.read(fd.stat.size) }

    self.new(mbdb_data, mbdx_data)
  end

  def parse_mbdb
    raise ArgumentError, "Not valid MBDB data" if self.mbdb_data[0,4] != "mbdb"
    self.mbdb_offset = 4
    self.mbdb_offset = self.mbdb_offset + 2 # Maps to \x05 \x00 (unknown)

    while self.mbdb_offset < self.mbdb_data.length
      info = {}
      info[:start_offset] = self.mbdb_offset
      info[:domain]       = mbdb_read_string
      info[:filename]     = mbdb_read_string
      info[:linktarget]   = mbdb_read_string
      info[:datahash]     = mbdb_read_string
      info[:unknown1]     = mbdb_read_string
      info[:mode]         = mbdb_read_int(2)
      info[:unknown2]     = mbdb_read_int(4)
      info[:unknown3]     = mbdb_read_int(4)
      info[:uid]          = mbdb_read_int(4)
      info[:gid]          = mbdb_read_int(4)
      info[:mtime]        = Time.at(mbdb_read_int(4))
      info[:atime]        = Time.at(mbdb_read_int(4))
      info[:ctime]        = Time.at(mbdb_read_int(4))
      info[:length]       = mbdb_read_int(8)
      info[:flag]         = mbdb_read_int(1)
      property_count      = mbdb_read_int(1)
      info[:properties]   = {}
      1.upto(property_count) do |i|
        k = mbdb_read_string
        v = mbdb_read_string
        info[:properties][k] = v
      end
      self.entry_offsets[ info[:start_offset] ] = info
    end
    self.mbdb_data = ""
  end

  def parse_mbdx
    raise ArgumentError, "Not a valid MBDX file" if self.mbdx_data[0,4] != "mbdx"

    self.mbdx_offset = 4
    self.mbdx_offset = self.mbdx_offset + 2 # Maps to \x02 \x00 (unknown)

    file_count = mbdx_read_int(4)

    while self.mbdx_offset < self.mbdx_data.length
      file_id = self.mbdx_data[self.mbdx_offset, 20].unpack("C*").map{|c| "%02x" % c}.join
      self.mbdx_offset += 20
      entry_offset = mbdx_read_int(4) + 6
      mode = mbdx_read_int(2)
      entry = entry_offsets[ entry_offset ]
      # May be corrupted if there is no matching entry, but what to do about it?
      next if not entry
      self.entries[file_id] = entry.merge({:mbdx_mode => mode, :file_id => file_id})
    end
    self.mbdx_data = ""
  end

  def mbdb_read_string
    raise RuntimeError, "Corrupted MBDB file" if self.mbdb_offset > self.mbdb_data.length
    len = self.mbdb_data[self.mbdb_offset, 2].unpack("n")[0]
    self.mbdb_offset += 2
    return '' if len == 65535
    val = self.mbdb_data[self.mbdb_offset, len]
    self.mbdb_offset += len
    return val
  end

  def mbdb_read_int(size)
    val = 0
    size.downto(1) do |i|
      val = (val << 8) + self.mbdb_data[self.mbdb_offset, 1].unpack("C")[0]
      self.mbdb_offset += 1
    end
    val
  end

  def mbdx_read_string
    raise RuntimeError, "Corrupted MBDX file" if self.mbdx_offset > self.mbdx_data.length
    len = self.mbdx_data[self.mbdx_offset, 2].unpack("n")[0]
    self.mbdx_offset += 2
    return '' if len == 65535
    val = self.mbdx_data[self.mbdx_offset, len]
    self.mbdx_offset += len
    return val
  end

  def mbdx_read_int(size)
    val = 0
    size.downto(1) do |i|
      val = (val << 8) + self.mbdx_data[self.mbdx_offset, 1].unpack("C")[0]
      self.mbdx_offset += 1
    end
 		val
  end
end


end
end
