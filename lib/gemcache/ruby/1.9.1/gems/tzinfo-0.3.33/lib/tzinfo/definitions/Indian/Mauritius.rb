module TZInfo
  module Definitions
    module Indian
      module Mauritius
        include TimezoneDefinition
        
        timezone 'Indian/Mauritius' do |tz|
          tz.offset :o0, 13800, 0, :LMT
          tz.offset :o1, 14400, 0, :MUT
          tz.offset :o2, 14400, 3600, :MUST
          
          tz.transition 1906, 12, :o1, 348130993, 144
          tz.transition 1982, 10, :o2, 403041600
          tz.transition 1983, 3, :o1, 417034800
          tz.transition 2008, 10, :o2, 1224972000
          tz.transition 2009, 3, :o1, 1238274000
        end
      end
    end
  end
end
