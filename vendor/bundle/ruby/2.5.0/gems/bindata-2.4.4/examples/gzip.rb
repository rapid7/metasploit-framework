require 'bindata'
require 'zlib'

# An example of a reader / writer for the GZIP file format as per rfc1952.
# See notes at the end of this file for implementation discussions.
class Gzip < BinData::Record
  # Binary representation of a ruby Time object
  class Mtime < BinData::Primitive
    uint32le :time

    def set(val)
      self.time = val.to_i
    end

    def get
      Time.at(time)
    end
  end

  # Known compression methods
  DEFLATE = 8

  endian :little

  uint16  :ident,      asserted_value: 0x8b1f
  uint8   :compression_method, initial_value: DEFLATE

  bit3    :freserved,  asserted_value: 0
  bit1    :fcomment,   value: -> { comment.length > 0 ? 1 : 0 }
  bit1    :ffile_name, value: -> { file_name.length > 0 ? 1 : 0 }
  bit1    :fextra,     value: -> { extra.len > 0 ? 1 : 0 }
  bit1    :fcrc16,     value: 0  # see note at end of file
  bit1    :ftext

  mtime   :mtime
  uint8   :extra_flags
  uint8   :os,         initial_value: 255   # unknown OS

  # The following fields are optional depending on the bits in flags

  struct  :extra,      onlyif: -> { fextra.nonzero? } do
    uint16 :len,  length: -> { data.length }
    string :data, read_length: :len
  end
  stringz :file_name,  onlyif: -> { ffile_name.nonzero? }
  stringz :comment,    onlyif: -> { fcomment.nonzero? }
  uint16  :crc16,      onlyif: -> { fcrc16.nonzero? }

  # The length of compressed data must be calculated from the current file offset
  count_bytes_remaining :bytes_remaining
  string :compressed_data, read_length: -> { bytes_remaining - footer.num_bytes }

  struct :footer do
    uint32 :crc32
    uint32 :uncompressed_size
  end

  def data=(data)
    # Zlib.deflate includes a header + footer which we must discard
    self.compressed_data = Zlib::Deflate.deflate(data)[2..-5]
    self.footer.crc32 = Zlib::crc32(data)
    self.footer.uncompressed_size = data.size
  end
end

if __FILE__ == $0
  # Write a gzip file.
  print "Creating a gzip file ... "
  g = Gzip.new
  g.data = "the cat sat on the mat"
  g.file_name = "poetry"
  g.mtime = Time.now
  g.comment = "A stunning piece of prose"
  File.open("poetry.gz", "w") do |io|
    g.write(io)
  end
  puts "done."
  puts

  # Read the created gzip file.
  print "Reading newly created gzip file ... "
  g = Gzip.new
  File.open("poetry.gz", "r") do |io|
    g.read(io)
  end
  puts "done."
  puts

  puts "Printing gzip file details in the format of gzip -l -v"

  # compression ratio
  ratio = 100.0 * (g.footer.uncompressed_size - g.compressed_data.size) /
            g.footer.uncompressed_size

  comp_meth = (g.compression_method == Gzip::DEFLATE) ? "defla" : ""

  # Output using the same format as gzip -l -v
  puts "method  crc     date  time           compressed        " +
       "uncompressed  ratio uncompressed_name"
  puts "%5s %08x %6s %5s %19s %19s %5.1f%% %s" % [comp_meth,
                                                  g.footer.crc32,
                                                  g.mtime.strftime('%b %d'),
                                                  g.mtime.strftime('%H:%M'),
                                                  g.num_bytes,
                                                  g.footer.uncompressed_size,
                                                  ratio,
                                                  g.file_name]
  puts "Comment: #{g.comment}" if g.comment?
  puts

  puts "Executing gzip -l -v"
  puts `gzip -l -v poetry.gz`
end

# Notes:
#
# Mtime: A convenience wrapper that allow a ruby Time object to be used instead
# of manually dealing with the raw form (seconds since 1 Jan 1970)
#
# rfc1952 specifies an optional crc16 field.  The gzip command line client
# uses this field for multi-part gzip.  Hence we ignore this.

# We are cheating and using the Zlib library for compression.  We can't use
# this library for decompression as zlib requires an adler32 checksum while
# gzip uses crc32.
