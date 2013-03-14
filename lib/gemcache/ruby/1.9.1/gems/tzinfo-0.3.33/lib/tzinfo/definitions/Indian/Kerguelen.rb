module TZInfo
  module Definitions
    module Indian
      module Kerguelen
        include TimezoneDefinition
        
        timezone 'Indian/Kerguelen' do |tz|
          tz.offset :o0, 0, 0, :zzz
          tz.offset :o1, 18000, 0, :TFT
          
          tz.transition 1950, 1, :o1, 4866565, 2
        end
      end
    end
  end
end
