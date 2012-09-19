module TZInfo
  module Definitions
    module America
      module Aruba
        include TimezoneDefinition
        
        timezone 'America/Aruba' do |tz|
          tz.offset :o0, -16824, 0, :LMT
          tz.offset :o1, -16200, 0, :ANT
          tz.offset :o2, -14400, 0, :AST
          
          tz.transition 1912, 2, :o1, 8710000901, 3600
          tz.transition 1965, 1, :o2, 39020187, 16
        end
      end
    end
  end
end
