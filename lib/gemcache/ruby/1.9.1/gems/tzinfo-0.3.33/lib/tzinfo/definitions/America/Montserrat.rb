module TZInfo
  module Definitions
    module America
      module Montserrat
        include TimezoneDefinition
        
        timezone 'America/Montserrat' do |tz|
          tz.offset :o0, -14932, 0, :LMT
          tz.offset :o1, -14400, 0, :AST
          
          tz.transition 1911, 7, :o1, 13063780837, 5400
        end
      end
    end
  end
end
