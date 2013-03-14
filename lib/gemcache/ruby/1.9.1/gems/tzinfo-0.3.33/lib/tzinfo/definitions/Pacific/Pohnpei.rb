module TZInfo
  module Definitions
    module Pacific
      module Pohnpei
        include TimezoneDefinition
        
        timezone 'Pacific/Pohnpei' do |tz|
          tz.offset :o0, 37972, 0, :LMT
          tz.offset :o1, 39600, 0, :PONT
          
          tz.transition 1900, 12, :o1, 52172317307, 21600
        end
      end
    end
  end
end
