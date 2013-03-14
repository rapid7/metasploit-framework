module TZInfo
  module Definitions
    module America
      module St_Kitts
        include TimezoneDefinition
        
        timezone 'America/St_Kitts' do |tz|
          tz.offset :o0, -15052, 0, :LMT
          tz.offset :o1, -14400, 0, :AST
          
          tz.transition 1912, 3, :o1, 52260415363, 21600
        end
      end
    end
  end
end
