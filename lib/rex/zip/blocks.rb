# -*- coding: binary -*-

module Rex
module Zip


#
# This structure holds the following data pertaining to a Zip entry's data.
#
# data crc
# compressed size
# uncompressed size
#
class CompInfo

  def initialize(crc, compsz, uncompsz)
    @crc, @compsz, @uncompsz = crc, compsz, uncompsz
  end

  def pack
    [ @crc, @compsz, @uncompsz ].pack('VVV')
  end

end


#
# This structure holds the following data pertaining to a Zip entry.
#
# general purpose bit flag
# compression method
# modification time
# modification date
#
class CompFlags

  attr_accessor :compmeth

  def initialize(gpbf, compmeth, timestamp)
    @gpbf = gpbf
    @compmeth = compmeth
    @mod_time = ((timestamp.hour << 11) | (timestamp.min << 5) | (timestamp.sec))
    @mod_date = (((timestamp.year - 1980) << 9) | (timestamp.mon << 5) | (timestamp.day))
  end

  def pack
    [ @gpbf, @compmeth, @mod_time, @mod_date ].pack('vvvv')
  end

end



#
# This structure is sometimes stored after the file data and used
# instead of the fields within the Local File Header.
#
class DataDesc

  SIGNATURE = 0x8074b50

  def initialize(compinfo)
    @compinfo = compinfo
  end

  def pack
    ret = [ SIGNATURE ].pack('V')
    ret << @compinfo.pack
    ret
  end

end


#
# This structure records the compression data and flags about
# a Zip entry to a file.
#
class LocalFileHdr

  SIGNATURE = 0x4034b50

  def initialize(entry)
    @entry = entry
  end

  def pack
    path = @entry.relative_path

    ret = [ SIGNATURE, ZIP_VERSION ].pack('Vv')
    ret << @entry.flags.pack
    ret << @entry.info.pack
    ret << [ path.length, @entry.xtra.length ].pack('vv')
    ret << path
    ret << @entry.xtra
    ret
  end

end


#
# This structure holds all of the information about a particular Zip Entry
# as it is contained within the central directory.
#
class CentralDir

  SIGNATURE = 0x2014b50

  def initialize(entry, offset)
    @entry = entry
    @disknum_start = 0
    @attr_int = 0
    @attr_ext = 0x20
    @hdr_offset = offset
  end

  def pack
    path = @entry.relative_path

    ret = [ SIGNATURE, ZIP_VERSION ].pack('Vv')
    ret << [ ZIP_VERSION ].pack('v')
    ret << @entry.flags.pack
    ret << @entry.info.pack
    arr = []
    arr << path.length
    arr << @entry.xtra.length
    arr << @entry.comment.length
    arr << @disknum_start
    arr << @attr_int
    arr << @entry.attrs
    arr << @hdr_offset
    ret << arr.pack('vvvvvVV')
    ret << path
    ret << @entry.xtra
    ret << @entry.comment
    # digital signature not supported
    ret
  end

end


#
# This structure is written after the per-entry central directory records to
# provide information about the archive as a whole.
#
class CentralDirEnd

  SIGNATURE = 0x6054b50

  def initialize(ncfd, cfdsz, offset, comment=nil)
    @disk_no = 0
    @disk_dir_start = 0
    @ncfd_this_disk = ncfd
    @ncfd_total = ncfd
    @cfd_size = cfdsz
    @start_offset = offset
    @comment = comment
    @comment ||= ''
  end


  def pack
    arr = []
    arr << SIGNATURE
    arr << @disk_no
    arr << @disk_dir_start
    arr << @ncfd_this_disk
    arr << @ncfd_total
    arr << @cfd_size
    arr << @start_offset
    arr << @comment.length
    (arr.pack('VvvvvVVv') + @comment)
  end

end

end
end
