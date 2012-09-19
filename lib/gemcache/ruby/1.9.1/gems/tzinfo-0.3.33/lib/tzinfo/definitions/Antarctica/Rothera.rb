module TZInfo
  module Definitions
    module Antarctica
      module Rothera
        include TimezoneDefinition
        
        timezone 'Antarctica/Rothera' do |tz|
          tz.offset :o0, 0, 0, :zzz
          tz.offset :o1, -10800, 0, :ROTT
          
          tz.transition 1976, 12, :o1, 218246400
        end
      end
    end
  end
end
