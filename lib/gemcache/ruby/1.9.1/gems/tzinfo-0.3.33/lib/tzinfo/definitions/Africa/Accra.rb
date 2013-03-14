module TZInfo
  module Definitions
    module Africa
      module Accra
        include TimezoneDefinition
        
        timezone 'Africa/Accra' do |tz|
          tz.offset :o0, -52, 0, :LMT
          tz.offset :o1, 0, 0, :GMT
          tz.offset :o2, 0, 1200, :GHST
          
          tz.transition 1918, 1, :o1, 52306441213, 21600
          tz.transition 1936, 9, :o2, 4856825, 2
          tz.transition 1936, 12, :o1, 174854411, 72
          tz.transition 1937, 9, :o2, 4857555, 2
          tz.transition 1937, 12, :o1, 174880691, 72
          tz.transition 1938, 9, :o2, 4858285, 2
          tz.transition 1938, 12, :o1, 174906971, 72
          tz.transition 1939, 9, :o2, 4859015, 2
          tz.transition 1939, 12, :o1, 174933251, 72
          tz.transition 1940, 9, :o2, 4859747, 2
          tz.transition 1940, 12, :o1, 174959603, 72
          tz.transition 1941, 9, :o2, 4860477, 2
          tz.transition 1941, 12, :o1, 174985883, 72
          tz.transition 1942, 9, :o2, 4861207, 2
          tz.transition 1942, 12, :o1, 175012163, 72
        end
      end
    end
  end
end
