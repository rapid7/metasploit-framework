module TZInfo
  module Definitions
    module Pacific
      module Wallis
        include TimezoneDefinition
        
        timezone 'Pacific/Wallis' do |tz|
          tz.offset :o0, 44120, 0, :LMT
          tz.offset :o1, 43200, 0, :WFT
          
          tz.transition 1900, 12, :o1, 5217231577, 2160
        end
      end
    end
  end
end
