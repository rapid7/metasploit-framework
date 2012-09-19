module TZInfo
  module Definitions
    module America
      module Grenada
        include TimezoneDefinition
        
        timezone 'America/Grenada' do |tz|
          tz.offset :o0, -14820, 0, :LMT
          tz.offset :o1, -14400, 0, :AST
          
          tz.transition 1911, 7, :o1, 3483674887, 1440
        end
      end
    end
  end
end
