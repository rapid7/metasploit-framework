module TZInfo
  module Definitions
    module Asia
      module Manila
        include TimezoneDefinition
        
        timezone 'Asia/Manila' do |tz|
          tz.offset :o0, -57360, 0, :LMT
          tz.offset :o1, 29040, 0, :LMT
          tz.offset :o2, 28800, 0, :PHT
          tz.offset :o3, 28800, 3600, :PHST
          tz.offset :o4, 32400, 0, :JST
          
          tz.transition 1844, 12, :o1, 862175579, 360
          tz.transition 1899, 5, :o2, 869322659, 360
          tz.transition 1936, 10, :o3, 14570839, 6
          tz.transition 1937, 1, :o2, 19428521, 8
          tz.transition 1942, 4, :o4, 14582881, 6
          tz.transition 1944, 10, :o2, 19451161, 8
          tz.transition 1954, 4, :o3, 14609065, 6
          tz.transition 1954, 6, :o2, 19479393, 8
          tz.transition 1978, 3, :o3, 259344000
          tz.transition 1978, 9, :o2, 275151600
        end
      end
    end
  end
end
