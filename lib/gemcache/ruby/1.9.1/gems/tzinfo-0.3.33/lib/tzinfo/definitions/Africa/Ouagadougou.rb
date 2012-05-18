module TZInfo
  module Definitions
    module Africa
      module Ouagadougou
        include TimezoneDefinition
        
        timezone 'Africa/Ouagadougou' do |tz|
          tz.offset :o0, -364, 0, :LMT
          tz.offset :o1, 0, 0, :GMT
          
          tz.transition 1912, 1, :o1, 52259094091, 21600
        end
      end
    end
  end
end
