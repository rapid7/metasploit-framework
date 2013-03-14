module TZInfo
  module Definitions
    module Africa
      module Libreville
        include TimezoneDefinition
        
        timezone 'Africa/Libreville' do |tz|
          tz.offset :o0, 2268, 0, :LMT
          tz.offset :o1, 3600, 0, :WAT
          
          tz.transition 1911, 12, :o1, 1935521979, 800
        end
      end
    end
  end
end
