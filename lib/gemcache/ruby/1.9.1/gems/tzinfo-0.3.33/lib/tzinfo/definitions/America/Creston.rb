module TZInfo
  module Definitions
    module America
      module Creston
        include TimezoneDefinition
        
        timezone 'America/Creston' do |tz|
          tz.offset :o0, -27964, 0, :LMT
          tz.offset :o1, -25200, 0, :MST
          tz.offset :o2, -28800, 0, :PST
          
          tz.transition 1884, 1, :o1, 52038219391, 21600
          tz.transition 1916, 10, :o2, 58107307, 24
          tz.transition 1918, 6, :o1, 14530481, 6
        end
      end
    end
  end
end
