module TZInfo
  module Definitions
    module Pacific
      module Norfolk
        include TimezoneDefinition
        
        timezone 'Pacific/Norfolk' do |tz|
          tz.offset :o0, 40312, 0, :LMT
          tz.offset :o1, 40320, 0, :NMT
          tz.offset :o2, 41400, 0, :NFT
          
          tz.transition 1900, 12, :o1, 26086158361, 10800
          tz.transition 1950, 12, :o2, 73009411, 30
        end
      end
    end
  end
end
