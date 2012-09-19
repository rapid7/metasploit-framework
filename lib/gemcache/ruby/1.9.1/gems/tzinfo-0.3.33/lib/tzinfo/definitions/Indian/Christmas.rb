module TZInfo
  module Definitions
    module Indian
      module Christmas
        include TimezoneDefinition
        
        timezone 'Indian/Christmas' do |tz|
          tz.offset :o0, 25372, 0, :LMT
          tz.offset :o1, 25200, 0, :CXT
          
          tz.transition 1895, 1, :o1, 52125664457, 21600
        end
      end
    end
  end
end
