
module Msf
  ###
  #
  # This module provides methods for WMAP Query Scanner modules
  #
  ###

  module Auxiliary::WmapScanQuery
    include Auxiliary::WmapModule

    def wmap_type
      :wmap_query
    end
  end

end