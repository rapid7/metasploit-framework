module TZInfo
  module Definitions
    module Africa
      module Gaborone
        include TimezoneDefinition
        
        timezone 'Africa/Gaborone' do |tz|
          tz.offset :o0, 6220, 0, :LMT
          tz.offset :o1, 7200, 0, :CAT
          tz.offset :o2, 7200, 3600, :CAST
          
          tz.transition 1884, 12, :o1, 10409223289, 4320
          tz.transition 1943, 9, :o2, 4861973, 2
          tz.transition 1944, 3, :o1, 58348043, 24
        end
      end
    end
  end
end
