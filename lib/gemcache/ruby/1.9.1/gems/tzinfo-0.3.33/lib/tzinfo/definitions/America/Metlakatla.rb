module TZInfo
  module Definitions
    module America
      module Metlakatla
        include TimezoneDefinition
        
        timezone 'America/Metlakatla' do |tz|
          tz.offset :o0, 54822, 0, :LMT
          tz.offset :o1, -31578, 0, :LMT
          tz.offset :o2, -28800, 0, :PST
          tz.offset :o3, -28800, 3600, :PWT
          tz.offset :o4, -28800, 3600, :PPT
          tz.offset :o5, -28800, 3600, :PDT
          tz.offset :o6, -28800, 0, :MeST
          
          tz.transition 1867, 10, :o1, 34606898863, 14400
          tz.transition 1900, 8, :o2, 34779634063, 14400
          tz.transition 1942, 2, :o3, 29164799, 12
          tz.transition 1945, 8, :o4, 58360379, 24
          tz.transition 1945, 9, :o2, 19453831, 8
          tz.transition 1969, 4, :o5, 29284067, 12
          tz.transition 1969, 10, :o2, 19524167, 8
          tz.transition 1970, 4, :o5, 9972000
          tz.transition 1970, 10, :o2, 25693200
          tz.transition 1971, 4, :o5, 41421600
          tz.transition 1971, 10, :o2, 57747600
          tz.transition 1972, 4, :o5, 73476000
          tz.transition 1972, 10, :o2, 89197200
          tz.transition 1973, 4, :o5, 104925600
          tz.transition 1973, 10, :o2, 120646800
          tz.transition 1974, 1, :o5, 126698400
          tz.transition 1974, 10, :o2, 152096400
          tz.transition 1975, 2, :o5, 162381600
          tz.transition 1975, 10, :o2, 183546000
          tz.transition 1976, 4, :o5, 199274400
          tz.transition 1976, 10, :o2, 215600400
          tz.transition 1977, 4, :o5, 230724000
          tz.transition 1977, 10, :o2, 247050000
          tz.transition 1978, 4, :o5, 262778400
          tz.transition 1978, 10, :o2, 278499600
          tz.transition 1979, 4, :o5, 294228000
          tz.transition 1979, 10, :o2, 309949200
          tz.transition 1980, 4, :o5, 325677600
          tz.transition 1980, 10, :o2, 341398800
          tz.transition 1981, 4, :o5, 357127200
          tz.transition 1981, 10, :o2, 372848400
          tz.transition 1982, 4, :o5, 388576800
          tz.transition 1982, 10, :o2, 404902800
          tz.transition 1983, 4, :o5, 420026400
          tz.transition 1983, 10, :o6, 436352400
        end
      end
    end
  end
end
