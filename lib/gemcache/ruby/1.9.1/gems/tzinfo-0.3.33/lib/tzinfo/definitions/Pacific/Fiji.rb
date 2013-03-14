module TZInfo
  module Definitions
    module Pacific
      module Fiji
        include TimezoneDefinition
        
        timezone 'Pacific/Fiji' do |tz|
          tz.offset :o0, 42820, 0, :LMT
          tz.offset :o1, 43200, 0, :FJT
          tz.offset :o2, 43200, 3600, :FJST
          
          tz.transition 1915, 10, :o1, 10457838739, 4320
          tz.transition 1998, 10, :o2, 909842400
          tz.transition 1999, 2, :o1, 920124000
          tz.transition 1999, 11, :o2, 941896800
          tz.transition 2000, 2, :o1, 951573600
          tz.transition 2009, 11, :o2, 1259416800
          tz.transition 2010, 3, :o1, 1269698400
          tz.transition 2010, 10, :o2, 1287842400
          tz.transition 2011, 3, :o1, 1299333600
          tz.transition 2011, 10, :o2, 1319292000
          tz.transition 2012, 1, :o1, 1327154400
        end
      end
    end
  end
end
