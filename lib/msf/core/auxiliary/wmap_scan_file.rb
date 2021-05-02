module Msf
  ###
  #
  # This module provides methods for WMAP File Scanner modules
  #
  ###

  module Auxiliary::WmapScanFile
    include Auxiliary::WmapModule

    def wmap_type
      :wmap_file
    end
  end
end
