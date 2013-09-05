# -*- coding: binary -*-

##
# Rex::OLE - an OLE implementation
# written in 2010 by Joshua J. Drake <jduck [at] metasploit.com>
##

module Rex
module OLE

class Property

  def initialize(id, type, data)
    @id = id
    @type = type
    @data = data
  end

  def pack_pio(off = 0)
    [ @id, off ].pack('V*')
  end

  def pack_data
    buf = [ @type ].pack('V')
    case @type
    when VT_BLOB
      buf << [ @data.length ].pack('V')
    when VT_CF
      buf << [ 4 + @data.length, -1 ].pack('V*')
    end
    buf << @data
    buf
  end

  def to_s
    "Rex::OLE::Property - to_s unimplemented"
  end

end

class PropertySet

  def initialize(fmtid = nil)
    @fmtid = CLSID.new(fmtid)
    @properties = []
  end

  def <<(val)
    @properties << val
  end

  def pack_fno(off = 0)
    @fmtid.pack + [ off ].pack('V')
  end

  def pack_data
    # Pack all the property data
    data = []
    dlen = 0
    @properties.each { |p|
      dat = p.pack_data
      dlen += dat.length
      data << dat
    }

    buf = ''
    # First the header
    off = 8 + (@properties.length * 8)
    buf << [ off + dlen, @properties.length ].pack('V*')
    # Now, the Property Id and Offset for each
    @properties.each_with_index { |p,x|
      buf << p.pack_pio(off)
      off += data[x].length
    }
    # Finally, all the data
    buf << data.join
    buf
  end

  def to_s
    "Rex::OLE::PropertySet - to_s unimplemented"
  end

end

class PropertySetStream

  def initialize
    @byte_order = 0xfffe
    @ole_version = 0
    @os_version = 1
    @os_platform = 2
    @clsid = CLSID.new

    @propsets = []
  end

  def <<(ps)
    @propsets << ps
  end

  def pack
    buf = ''

    # First, add the header
    buf << [
      @byte_order,
      @ole_version,
      @os_version,
      @os_platform
    ].pack('vvvv')
    buf << @clsid.pack
    buf << [@propsets.length].pack('V')

    # Pack all the PropertySet children
    data = []
    @propsets.each { |p|
      data << p.pack_data
    }

    # Next, add all the FMTID and Offset headers
    off = buf.length + (20 * @propsets.length)
    @propsets.each_with_index { |ps,x|
      buf << ps.pack_fno(off)
      off += data[x].length
    }

    # Finally, add all the data
    buf << data.join
    buf
  end

  def to_s
    "Rex::OLE::PropertySetStream - to_s unimplemented"
  end

end


end
end
