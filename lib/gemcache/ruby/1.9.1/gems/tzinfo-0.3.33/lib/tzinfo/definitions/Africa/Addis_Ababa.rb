module TZInfo
  module Definitions
    module Africa
      module Addis_Ababa
        include TimezoneDefinition
        
        timezone 'Africa/Addis_Ababa' do |tz|
          tz.offset :o0, 9288, 0, :LMT
          tz.offset :o1, 9320, 0, :ADMT
          tz.offset :o2, 10800, 0, :EAT
          
          tz.transition 1869, 12, :o1, 961625357, 400
          tz.transition 1936, 5, :o2, 5245113727, 2160
        end
      end
    end
  end
end
