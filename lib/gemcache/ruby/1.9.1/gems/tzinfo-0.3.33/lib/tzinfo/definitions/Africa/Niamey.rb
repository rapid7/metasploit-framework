module TZInfo
  module Definitions
    module Africa
      module Niamey
        include TimezoneDefinition
        
        timezone 'Africa/Niamey' do |tz|
          tz.offset :o0, 508, 0, :LMT
          tz.offset :o1, -3600, 0, :WAT
          tz.offset :o2, 0, 0, :GMT
          tz.offset :o3, 3600, 0, :WAT
          
          tz.transition 1911, 12, :o1, 52259093873, 21600
          tz.transition 1934, 2, :o2, 58259869, 24
          tz.transition 1960, 1, :o3, 4873869, 2
        end
      end
    end
  end
end
