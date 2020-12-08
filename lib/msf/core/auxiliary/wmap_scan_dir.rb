module Msf
  ###
  #
  # This module provides methods for WMAP Directory Scanner modules
  #
  ###

  module Auxiliary::WmapScanDir
    include Auxiliary::WmapModule

    def wmap_type
      :wmap_dir
    end
  end

end
