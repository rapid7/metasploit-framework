module TZInfo
  module Definitions
    module America
      module St_Lucia
        include TimezoneDefinition
        
        timezone 'America/St_Lucia' do |tz|
          tz.offset :o0, -14640, 0, :LMT
          tz.offset :o1, -14640, 0, :CMT
          tz.offset :o2, -14400, 0, :AST
          
          tz.transition 1890, 1, :o1, 868092721, 360
          tz.transition 1912, 1, :o2, 870984961, 360
        end
      end
    end
  end
end
