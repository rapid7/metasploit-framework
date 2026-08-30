
module Msf
  ###
  #
  # This module provides methods for WMAP Web Server Scanner modules
  #
  ###

  module Auxiliary::WmapScanServer
    include Auxiliary::WmapModule

    def wmap_type
      :wmap_server
    end
  end
end