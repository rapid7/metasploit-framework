module TZInfo
  module Definitions
    module Asia
      module Aden
        include TimezoneDefinition
        
        timezone 'Asia/Aden' do |tz|
          tz.offset :o0, 10848, 0, :LMT
          tz.offset :o1, 10800, 0, :AST
          
          tz.transition 1949, 12, :o1, 2189954137, 900
        end
      end
    end
  end
end
