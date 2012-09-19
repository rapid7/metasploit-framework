module TZInfo
  module Definitions
    module Africa
      module El_Aaiun
        include TimezoneDefinition
        
        timezone 'Africa/El_Aaiun' do |tz|
          tz.offset :o0, -3168, 0, :LMT
          tz.offset :o1, -3600, 0, :WAT
          tz.offset :o2, 0, 0, :WET
          
          tz.transition 1934, 1, :o1, 728231561, 300
          tz.transition 1976, 4, :o2, 198291600
        end
      end
    end
  end
end
