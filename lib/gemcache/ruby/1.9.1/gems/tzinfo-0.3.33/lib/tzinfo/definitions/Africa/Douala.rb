module TZInfo
  module Definitions
    module Africa
      module Douala
        include TimezoneDefinition
        
        timezone 'Africa/Douala' do |tz|
          tz.offset :o0, 2328, 0, :LMT
          tz.offset :o1, 3600, 0, :WAT
          
          tz.transition 1911, 12, :o1, 8709848903, 3600
        end
      end
    end
  end
end
