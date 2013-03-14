module TZInfo
  module Definitions
    module Pacific
      module Johnston
        include TimezoneDefinition
        
        timezone 'Pacific/Johnston' do |tz|
          tz.offset :o0, -36000, 0, :HST
          
        end
      end
    end
  end
end
