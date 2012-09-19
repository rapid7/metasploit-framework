module TZInfo
  module Definitions
    module Asia
      module Makassar
        include TimezoneDefinition
        
        timezone 'Asia/Makassar' do |tz|
          tz.offset :o0, 28656, 0, :LMT
          tz.offset :o1, 28656, 0, :MMT
          tz.offset :o2, 28800, 0, :CIT
          tz.offset :o3, 32400, 0, :JST
          
          tz.transition 1919, 12, :o1, 1453394501, 600
          tz.transition 1932, 10, :o2, 1456207301, 600
          tz.transition 1942, 2, :o3, 14582395, 6
          tz.transition 1945, 9, :o2, 19453769, 8
        end
      end
    end
  end
end
