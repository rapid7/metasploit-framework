module TZInfo
  module Definitions
    module Africa
      module Freetown
        include TimezoneDefinition
        
        timezone 'Africa/Freetown' do |tz|
          tz.offset :o0, -3180, 0, :LMT
          tz.offset :o1, -3180, 0, :FMT
          tz.offset :o2, -3600, 0, :WAT
          tz.offset :o3, -3600, 2400, :SLST
          tz.offset :o4, 0, 0, :WAT
          tz.offset :o5, 0, 3600, :SLST
          tz.offset :o6, 0, 0, :GMT
          
          tz.transition 1882, 1, :o1, 3468163013, 1440
          tz.transition 1913, 6, :o2, 3484684133, 1440
          tz.transition 1935, 6, :o3, 58270909, 24
          tz.transition 1935, 10, :o2, 174821509, 72
          tz.transition 1936, 6, :o3, 58279693, 24
          tz.transition 1936, 10, :o2, 174847861, 72
          tz.transition 1937, 6, :o3, 58288453, 24
          tz.transition 1937, 10, :o2, 174874141, 72
          tz.transition 1938, 6, :o3, 58297213, 24
          tz.transition 1938, 10, :o2, 174900421, 72
          tz.transition 1939, 6, :o3, 58305973, 24
          tz.transition 1939, 10, :o2, 174926701, 72
          tz.transition 1940, 6, :o3, 58314757, 24
          tz.transition 1940, 10, :o2, 174953053, 72
          tz.transition 1941, 6, :o3, 58323517, 24
          tz.transition 1941, 10, :o2, 174979333, 72
          tz.transition 1942, 6, :o3, 58332277, 24
          tz.transition 1942, 10, :o2, 175005613, 72
          tz.transition 1957, 1, :o4, 58460149, 24
          tz.transition 1957, 6, :o5, 4871981, 2
          tz.transition 1957, 8, :o6, 58465979, 24
          tz.transition 1958, 6, :o5, 4872711, 2
          tz.transition 1958, 8, :o6, 58474739, 24
          tz.transition 1959, 6, :o5, 4873441, 2
          tz.transition 1959, 8, :o6, 58483499, 24
          tz.transition 1960, 6, :o5, 4874173, 2
          tz.transition 1960, 8, :o6, 58492283, 24
          tz.transition 1961, 6, :o5, 4874903, 2
          tz.transition 1961, 8, :o6, 58501043, 24
          tz.transition 1962, 6, :o5, 4875633, 2
          tz.transition 1962, 8, :o6, 58509803, 24
        end
      end
    end
  end
end
