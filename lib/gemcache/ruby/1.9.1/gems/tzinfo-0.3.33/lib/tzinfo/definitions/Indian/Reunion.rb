module TZInfo
  module Definitions
    module Indian
      module Reunion
        include TimezoneDefinition
        
        timezone 'Indian/Reunion' do |tz|
          tz.offset :o0, 13312, 0, :LMT
          tz.offset :o1, 14400, 0, :RET
          
          tz.transition 1911, 5, :o1, 3265904267, 1350
        end
      end
    end
  end
end
