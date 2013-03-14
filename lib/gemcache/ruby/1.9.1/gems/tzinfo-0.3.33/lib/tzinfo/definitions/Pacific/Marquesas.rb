module TZInfo
  module Definitions
    module Pacific
      module Marquesas
        include TimezoneDefinition
        
        timezone 'Pacific/Marquesas' do |tz|
          tz.offset :o0, -33480, 0, :LMT
          tz.offset :o1, -34200, 0, :MART
          
          tz.transition 1912, 10, :o1, 193574151, 80
        end
      end
    end
  end
end
