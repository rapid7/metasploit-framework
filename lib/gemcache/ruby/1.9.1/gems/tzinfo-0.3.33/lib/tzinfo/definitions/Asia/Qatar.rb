module TZInfo
  module Definitions
    module Asia
      module Qatar
        include TimezoneDefinition
        
        timezone 'Asia/Qatar' do |tz|
          tz.offset :o0, 12368, 0, :LMT
          tz.offset :o1, 14400, 0, :GST
          tz.offset :o2, 10800, 0, :AST
          
          tz.transition 1919, 12, :o1, 13080551527, 5400
          tz.transition 1972, 5, :o2, 76190400
        end
      end
    end
  end
end
