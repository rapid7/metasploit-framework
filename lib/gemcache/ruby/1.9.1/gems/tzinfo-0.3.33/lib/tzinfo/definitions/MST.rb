module TZInfo
  module Definitions
    module MST
      include TimezoneDefinition
      
      timezone 'MST' do |tz|
        tz.offset :o0, -25200, 0, :MST
        
      end
    end
  end
end
