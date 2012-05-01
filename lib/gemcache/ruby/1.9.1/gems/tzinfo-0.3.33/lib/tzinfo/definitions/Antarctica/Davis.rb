module TZInfo
  module Definitions
    module Antarctica
      module Davis
        include TimezoneDefinition
        
        timezone 'Antarctica/Davis' do |tz|
          tz.offset :o0, 0, 0, :zzz
          tz.offset :o1, 25200, 0, :DAVT
          tz.offset :o2, 18000, 0, :DAVT
          
          tz.transition 1957, 1, :o1, 4871703, 2
          tz.transition 1964, 10, :o0, 58528805, 24
          tz.transition 1969, 2, :o1, 4880507, 2
          tz.transition 2009, 10, :o2, 1255806000
          tz.transition 2010, 3, :o1, 1268251200
          tz.transition 2011, 10, :o2, 1319742000
          tz.transition 2012, 2, :o1, 1329854400
        end
      end
    end
  end
end
