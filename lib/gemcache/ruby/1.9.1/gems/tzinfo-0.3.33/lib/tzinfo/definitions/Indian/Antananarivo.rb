module TZInfo
  module Definitions
    module Indian
      module Antananarivo
        include TimezoneDefinition
        
        timezone 'Indian/Antananarivo' do |tz|
          tz.offset :o0, 11404, 0, :LMT
          tz.offset :o1, 10800, 0, :EAT
          tz.offset :o2, 10800, 3600, :EAST
          
          tz.transition 1911, 6, :o1, 52255116749, 21600
          tz.transition 1954, 2, :o2, 7304404, 3
          tz.transition 1954, 5, :o1, 7304677, 3
        end
      end
    end
  end
end
