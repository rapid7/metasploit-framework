module TZInfo
  module Definitions
    module Pacific
      module Guadalcanal
        include TimezoneDefinition
        
        timezone 'Pacific/Guadalcanal' do |tz|
          tz.offset :o0, 38388, 0, :LMT
          tz.offset :o1, 39600, 0, :SBT
          
          tz.transition 1912, 9, :o1, 17421667601, 7200
        end
      end
    end
  end
end
