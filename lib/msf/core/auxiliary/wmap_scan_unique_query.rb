
module Msf
  ###
  #
  # This module provides methods for WMAP Unique Query Scanner modules
  #
  ###

  module Auxiliary::WmapScanUniqueQuery
    include Auxiliary::WmapModule

    def wmap_type
      :wmap_unique_query
    end

    def signature(fpath,fquery)
      hsig = Hash.new()

      hsig = queryparse(fquery)

      #
      # Signature of the form ',p1,p2,pn' then to be appended to path: path,p1,p2,pn
      #

      sigstr = fpath + "," + hsig.map{|p| p[0].to_s}.join(",")
    end
  end

end