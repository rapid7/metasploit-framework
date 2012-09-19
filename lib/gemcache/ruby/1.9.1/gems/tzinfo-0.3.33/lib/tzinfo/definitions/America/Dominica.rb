module TZInfo
  module Definitions
    module America
      module Dominica
        include TimezoneDefinition
        
        timezone 'America/Dominica' do |tz|
          tz.offset :o0, -14736, 0, :LMT
          tz.offset :o1, -14400, 0, :AST
          
          tz.transition 1911, 7, :o1, 1935374937, 800
        end
      end
    end
  end
end
