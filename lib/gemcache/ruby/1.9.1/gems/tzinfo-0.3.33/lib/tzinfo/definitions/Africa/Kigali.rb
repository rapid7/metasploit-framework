module TZInfo
  module Definitions
    module Africa
      module Kigali
        include TimezoneDefinition
        
        timezone 'Africa/Kigali' do |tz|
          tz.offset :o0, 7216, 0, :LMT
          tz.offset :o1, 7200, 0, :CAT
          
          tz.transition 1935, 5, :o1, 13110953849, 5400
        end
      end
    end
  end
end
