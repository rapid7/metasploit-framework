module TZInfo
  module Definitions
    module America
      module Guadeloupe
        include TimezoneDefinition
        
        timezone 'America/Guadeloupe' do |tz|
          tz.offset :o0, -14768, 0, :LMT
          tz.offset :o1, -14400, 0, :AST
          
          tz.transition 1911, 6, :o1, 13063656623, 5400
        end
      end
    end
  end
end
