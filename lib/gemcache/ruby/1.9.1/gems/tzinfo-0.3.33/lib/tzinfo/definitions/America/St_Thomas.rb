module TZInfo
  module Definitions
    module America
      module St_Thomas
        include TimezoneDefinition
        
        timezone 'America/St_Thomas' do |tz|
          tz.offset :o0, -15584, 0, :LMT
          tz.offset :o1, -14400, 0, :AST
          
          tz.transition 1911, 7, :o1, 6531890437, 2700
        end
      end
    end
  end
end
