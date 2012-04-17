module TZInfo
  module Definitions
    module Africa
      module Nouakchott
        include TimezoneDefinition
        
        timezone 'Africa/Nouakchott' do |tz|
          tz.offset :o0, -3828, 0, :LMT
          tz.offset :o1, 0, 0, :GMT
          tz.offset :o2, -3600, 0, :WAT
          
          tz.transition 1912, 1, :o1, 17419698319, 7200
          tz.transition 1934, 2, :o2, 4854989, 2
          tz.transition 1960, 11, :o1, 58494397, 24
        end
      end
    end
  end
end
