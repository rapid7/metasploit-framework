module TZInfo
  module Definitions
    module Africa
      module Sao_Tome
        include TimezoneDefinition
        
        timezone 'Africa/Sao_Tome' do |tz|
          tz.offset :o0, 1616, 0, :LMT
          tz.offset :o1, -2192, 0, :LMT
          tz.offset :o2, 0, 0, :GMT
          
          tz.transition 1883, 12, :o1, 13009552999, 5400
          tz.transition 1912, 1, :o2, 13064773637, 5400
        end
      end
    end
  end
end
