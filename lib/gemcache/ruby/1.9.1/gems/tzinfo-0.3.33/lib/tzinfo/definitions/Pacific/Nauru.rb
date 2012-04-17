module TZInfo
  module Definitions
    module Pacific
      module Nauru
        include TimezoneDefinition
        
        timezone 'Pacific/Nauru' do |tz|
          tz.offset :o0, 40060, 0, :LMT
          tz.offset :o1, 41400, 0, :NRT
          tz.offset :o2, 32400, 0, :JST
          tz.offset :o3, 43200, 0, :NRT
          
          tz.transition 1921, 1, :o1, 10466081437, 4320
          tz.transition 1942, 3, :o2, 116660785, 48
          tz.transition 1944, 8, :o1, 19450537, 8
          tz.transition 1979, 4, :o3, 294323400
        end
      end
    end
  end
end
