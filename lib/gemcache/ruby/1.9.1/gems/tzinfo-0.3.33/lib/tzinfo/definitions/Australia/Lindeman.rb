module TZInfo
  module Definitions
    module Australia
      module Lindeman
        include TimezoneDefinition
        
        timezone 'Australia/Lindeman' do |tz|
          tz.offset :o0, 35756, 0, :LMT
          tz.offset :o1, 36000, 0, :EST
          tz.offset :o2, 36000, 3600, :EST
          
          tz.transition 1894, 12, :o1, 52124992261, 21600
          tz.transition 1916, 12, :o2, 3486569881, 1440
          tz.transition 1917, 3, :o1, 19370497, 8
          tz.transition 1941, 12, :o2, 14582161, 6
          tz.transition 1942, 3, :o1, 19443577, 8
          tz.transition 1942, 9, :o2, 14583775, 6
          tz.transition 1943, 3, :o1, 19446489, 8
          tz.transition 1943, 10, :o2, 14586001, 6
          tz.transition 1944, 3, :o1, 19449401, 8
          tz.transition 1971, 10, :o2, 57686400
          tz.transition 1972, 2, :o1, 67968000
          tz.transition 1989, 10, :o2, 625593600
          tz.transition 1990, 3, :o1, 636480000
          tz.transition 1990, 10, :o2, 657043200
          tz.transition 1991, 3, :o1, 667929600
          tz.transition 1991, 10, :o2, 688492800
          tz.transition 1992, 2, :o1, 699379200
          tz.transition 1992, 10, :o2, 719942400
          tz.transition 1993, 3, :o1, 731433600
          tz.transition 1993, 10, :o2, 751996800
          tz.transition 1994, 3, :o1, 762883200
        end
      end
    end
  end
end
