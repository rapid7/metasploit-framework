module TZInfo
  module Definitions
    module Asia
      module Dubai
        include TimezoneDefinition
        
        timezone 'Asia/Dubai' do |tz|
          tz.offset :o0, 13272, 0, :LMT
          tz.offset :o1, 14400, 0, :GST
          
          tz.transition 1919, 12, :o1, 8720367647, 3600
        end
      end
    end
  end
end
