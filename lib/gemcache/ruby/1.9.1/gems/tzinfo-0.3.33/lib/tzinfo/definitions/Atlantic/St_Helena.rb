module TZInfo
  module Definitions
    module Atlantic
      module St_Helena
        include TimezoneDefinition
        
        timezone 'Atlantic/St_Helena' do |tz|
          tz.offset :o0, -1368, 0, :LMT
          tz.offset :o1, -1368, 0, :JMT
          tz.offset :o2, 0, 0, :GMT
          
          tz.transition 1890, 1, :o1, 2893642219, 1200
          tz.transition 1951, 1, :o2, 2920377019, 1200
        end
      end
    end
  end
end
