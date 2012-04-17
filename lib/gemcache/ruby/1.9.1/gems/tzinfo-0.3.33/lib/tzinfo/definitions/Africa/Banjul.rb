module TZInfo
  module Definitions
    module Africa
      module Banjul
        include TimezoneDefinition
        
        timezone 'Africa/Banjul' do |tz|
          tz.offset :o0, -3996, 0, :LMT
          tz.offset :o1, -3996, 0, :BMT
          tz.offset :o2, -3600, 0, :WAT
          tz.offset :o3, 0, 0, :GMT
          
          tz.transition 1912, 1, :o1, 1935522037, 800
          tz.transition 1935, 1, :o2, 1942242837, 800
          tz.transition 1964, 1, :o3, 58521493, 24
        end
      end
    end
  end
end
