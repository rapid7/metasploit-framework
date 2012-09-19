module TZInfo
  module Definitions
    module Asia
      module Pontianak
        include TimezoneDefinition
        
        timezone 'Asia/Pontianak' do |tz|
          tz.offset :o0, 26240, 0, :LMT
          tz.offset :o1, 26240, 0, :PMT
          tz.offset :o2, 27000, 0, :WIT
          tz.offset :o3, 32400, 0, :JST
          tz.offset :o4, 28800, 0, :WIT
          tz.offset :o5, 28800, 0, :CIT
          tz.offset :o6, 25200, 0, :WIT
          
          tz.transition 1908, 4, :o1, 652876793, 270
          tz.transition 1932, 10, :o2, 655293293, 270
          tz.transition 1942, 1, :o3, 38886211, 16
          tz.transition 1945, 9, :o2, 19453769, 8
          tz.transition 1948, 4, :o4, 38922755, 16
          tz.transition 1950, 4, :o2, 14600413, 6
          tz.transition 1963, 12, :o5, 39014323, 16
          tz.transition 1987, 12, :o6, 567964800
        end
      end
    end
  end
end
