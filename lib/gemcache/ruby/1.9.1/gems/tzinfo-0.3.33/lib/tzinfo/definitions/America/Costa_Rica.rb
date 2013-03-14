module TZInfo
  module Definitions
    module America
      module Costa_Rica
        include TimezoneDefinition
        
        timezone 'America/Costa_Rica' do |tz|
          tz.offset :o0, -20180, 0, :LMT
          tz.offset :o1, -20180, 0, :SJMT
          tz.offset :o2, -21600, 0, :CST
          tz.offset :o3, -21600, 3600, :CDT
          
          tz.transition 1890, 1, :o1, 10417112929, 4320
          tz.transition 1921, 1, :o2, 10466084449, 4320
          tz.transition 1979, 2, :o3, 288770400
          tz.transition 1979, 6, :o2, 297234000
          tz.transition 1980, 2, :o3, 320220000
          tz.transition 1980, 6, :o2, 328683600
          tz.transition 1991, 1, :o3, 664264800
          tz.transition 1991, 7, :o2, 678344400
          tz.transition 1992, 1, :o3, 695714400
          tz.transition 1992, 3, :o2, 700635600
        end
      end
    end
  end
end
