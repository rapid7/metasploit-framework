module TZInfo
  module Definitions
    module America
      module St_Vincent
        include TimezoneDefinition
        
        timezone 'America/St_Vincent' do |tz|
          tz.offset :o0, -14696, 0, :LMT
          tz.offset :o1, -14696, 0, :KMT
          tz.offset :o2, -14400, 0, :AST
          
          tz.transition 1890, 1, :o1, 26042781637, 10800
          tz.transition 1912, 1, :o2, 26129548837, 10800
        end
      end
    end
  end
end
