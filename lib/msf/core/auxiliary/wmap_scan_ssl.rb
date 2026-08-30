module Msf
###
#
# This module provides methods for WMAP SSL Scanner modules
#
###

module Auxiliary::WmapScanSSL
  include Auxiliary::WmapModule

  def wmap_type
    :wmap_ssl
  end
end
end