#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/image_source/image_source'
require 'rex/struct2'

module Rex
module ImageSource
class Memory < ImageSource

  attr_accessor :rawdata, :size, :file_offset

  def initialize(_rawdata, _file_offset = 0)
    self.rawdata     = _rawdata
    self.size        = _rawdata.length
    self.file_offset = _file_offset
  end

  def read(offset, len)
    rawdata[offset, len]
  end

  def subsource(offset, len)
    self.class.new(rawdata[offset, len], offset + file_offset)
  end

  def close
  end

  def index(*args)
    rawdata.index(*args)
  end
end

end
end
