# -*- coding: binary -*-

require 'rex/image_source/image_source'
require 'rex/struct2'

module Rex
module ImageSource
class Disk < ImageSource

  attr_accessor :file, :file_offset, :size

  WINDOW_SIZE     = 4096
  WINDOW_OVERLAP  = 64

  def initialize(_file, _offset = 0, _len = nil)
    _len = _file.stat.size if !_len

    self.file         = _file
    self.file_offset  = _offset
    self.size         = _len
  end

  def read(offset, len)
    if offset < 0 || offset+len > size
      raise RangeError, "Offset #{offset} outside of image source", caller
    end

    file.seek(file_offset + offset)
    file.read(len)
  end

  def index(search, offset = 0)
    # do a sliding window search across the disk
    while offset < size

      # get a full window size if we can, we
      # don't want to read past our boundaries
      wsize = size - offset
      wsize = WINDOW_SIZE if wsize > WINDOW_SIZE

      window = self.read(offset, wsize)
      res = window.index(search)
      return res + offset if res
      offset += WINDOW_SIZE - WINDOW_OVERLAP
    end
  end

  def subsource(offset, len)
    self.class.new(file, file_offset+offset, len)
  end

  def close
    file.close
  end
end

end
end
