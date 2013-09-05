# -*- coding: binary -*-

##
# Rex::OLE - an OLE implementation
# written in 2010 by Joshua J. Drake <jduck [at] metasploit.com>
##

module Rex
module OLE

class SubStorage < DirEntry

  def initialize(stg)
    super

    @_mse = STGTY_STORAGE
  end


  def close
  end


  # stream handling stuff
  def create_stream(name, mode=STGM_WRITE)
    @stg.create_stream(name, mode, self)
  end

  def open_stream(name, mode=STGM_READ)
    @stg.open_stream(name, mode, self)
  end


  # storage handling stuff
  def create_storage(name, mode=STGM_WRITE)
    @stg.create_storage(name, mode, self)
  end

  def open_storage(name, mode=STGM_WRITE)
    @stg.open_storage(name, mode, self)
  end

end

end
end
