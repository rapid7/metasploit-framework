module TZInfo
  module Definitions
    module America
      module Cayenne
        include TimezoneDefinition
        
        timezone 'America/Cayenne' do |tz|
          tz.offset :o0, -12560, 0, :LMT
          tz.offset :o1, -14400, 0, :GFT
          tz.offset :o2, -10800, 0, :GFT
          
          tz.transition 1911, 7, :o1, 2612756137, 1080
          tz.transition 1967, 10, :o2, 7319294, 3
        end
      end
    end
  end
end
