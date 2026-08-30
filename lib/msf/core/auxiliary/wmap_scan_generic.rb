module Msf
  module Auxiliary::WmapScanGeneric
    include Auxiliary::WmapModule

    def wmap_type
      :wmap_generic
    end
  end
end