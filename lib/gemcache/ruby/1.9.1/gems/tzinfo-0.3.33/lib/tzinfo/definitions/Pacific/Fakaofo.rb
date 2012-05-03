module TZInfo
  module Definitions
    module Pacific
      module Fakaofo
        include TimezoneDefinition
        
        timezone 'Pacific/Fakaofo' do |tz|
          tz.offset :o0, -41096, 0, :LMT
          tz.offset :o1, -36000, 0, :TKT
          tz.offset :o2, 50400, 0, :TKT
          
          tz.transition 1901, 1, :o1, 26086168537, 10800
          tz.transition 2011, 12, :o2, 1325239200
        end
      end
    end
  end
end
