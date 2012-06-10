module TZInfo
  module Definitions
    module Pacific
      module Chuuk
        include TimezoneDefinition
        
        timezone 'Pacific/Chuuk' do |tz|
          tz.offset :o0, 36428, 0, :LMT
          tz.offset :o1, 36000, 0, :CHUT
          
          tz.transition 1900, 12, :o1, 52172317693, 21600
        end
      end
    end
  end
end
