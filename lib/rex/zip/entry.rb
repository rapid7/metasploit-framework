# -*- coding: binary -*-

module Rex
module Zip

#
# An Entry represents a logical file or directory to be stored in an Archive
#
class Entry

  attr_accessor :name, :flags, :info, :xtra, :comment, :attrs, :central_dir_name
  attr_reader :data

  def initialize(fname, data, compmeth, timestamp=nil, attrs=nil, xtra=nil, comment=nil, central_dir_name=nil)
    @name = fname.unpack("C*").pack("C*")
    @central_dir_name = (central_dir_name ? central_dir_name.unpack("C*").pack("C*") : nil)
    @data = data.unpack("C*").pack("C*")
    @xtra = xtra
    @xtra ||= ''
    @comment = comment
    @comment ||= ''
    @attrs = attrs
    @attrs ||= 0

    # XXX: sanitize timestmap (assume now)
    timestamp ||= Time.now
    @flags = CompFlags.new(0, compmeth, timestamp)

    if (@data)
      compress
    else
      @data = ''
      @info = CompInfo.new(0, 0, 0)
    end
    @compdata ||= ''
  end

  def data=(val)
    @data = val.unpack("C*").pack("C*")
    compress
  end

  #
  # Compress the #data and store it for later use.  If this entry's compression method
  # produces a larger blob than the original data, the method is changed to CM_STORE.
  #
  def compress
    @crc = Zlib.crc32(@data, 0)
    case @flags.compmeth

    when CM_STORE
      @compdata = @data

    when CM_DEFLATE
      z = Zlib::Deflate.new(Zlib::BEST_COMPRESSION)
      @compdata = z.deflate(@data, Zlib::FINISH)
      z.close
      @compdata = @compdata[2, @compdata.length-6]

    else
      raise 'Unsupported compression method: %u' % @flags.compmeth
    end

    # if compressing doesn't help, just store it
    if (@compdata.length > @data.length)
      @compdata = @data
      @flags.compmeth = CM_STORE
    end

    @info = CompInfo.new(@crc, @compdata.length, @data.length)
  end


  def relative_path
    get_relative_path(@name)
  end

  def central_dir_path
    return nil if @central_dir_name.blank?
    get_relative_path(@central_dir_name)
  end


  #
  # Return the compressed data in a format suitable for adding to an Archive
  #
  def pack
    #  - lfh 1
    lfh = LocalFileHdr.new(self)
    ret = lfh.pack

    #  - data 1
    if (@compdata)
      ret << @compdata
    end

    if (@gpbf & GPBF_USE_DATADESC)
      #  - data desc 1
      dd = DataDesc.new(@info)
      ret << dd.pack
    end

    ret
  end

  def inspect
    "#<#{self.class} name:#{name}, data:#{@data.length} bytes>"
  end

  private

  def get_relative_path(path)
    if (path[0,1] == '/')
      return path[1, path.length]
    end
    path
  end

end

end
end
