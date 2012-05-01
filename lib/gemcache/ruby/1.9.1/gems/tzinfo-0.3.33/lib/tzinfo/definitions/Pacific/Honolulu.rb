module TZInfo
  module Definitions
    module Pacific
      module Honolulu
        include TimezoneDefinition
        
        timezone 'Pacific/Honolulu' do |tz|
          tz.offset :o0, -37886, 0, :LMT
          tz.offset :o1, -37800, 0, :HST
          tz.offset :o2, -37800, 3600, :HDT
          tz.offset :o3, -36000, 0, :HST
          
          tz.transition 1896, 1, :o1, 104266329343, 43200
          tz.transition 1933, 4, :o2, 116505265, 48
          tz.transition 1933, 5, :o1, 116506291, 48
          tz.transition 1942, 2, :o2, 116659201, 48
          tz.transition 1945, 9, :o1, 116722991, 48
          tz.transition 1947, 6, :o3, 116752561, 48
        end
      end
    end
  end
end
