module Msf
  ###
  #
  # This module provides methods for WMAP Crawler modules
  #
  ###

  module Auxiliary::WmapCrawler
    include Auxiliary::WmapModule

    def wmap_type
      :wmap_crawler
    end
  end
end
