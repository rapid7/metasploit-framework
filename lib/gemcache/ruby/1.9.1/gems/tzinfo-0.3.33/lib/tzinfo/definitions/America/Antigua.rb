module TZInfo
  module Definitions
    module America
      module Antigua
        include TimezoneDefinition
        
        timezone 'America/Antigua' do |tz|
          tz.offset :o0, -14832, 0, :LMT
          tz.offset :o1, -18000, 0, :EST
          tz.offset :o2, -14400, 0, :AST
          
          tz.transition 1912, 3, :o1, 1451678203, 600
          tz.transition 1951, 1, :o2, 58407545, 24
        end
      end
    end
  end
end
