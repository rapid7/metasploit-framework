module TZInfo
  module Definitions
    module Africa
      module Kinshasa
        include TimezoneDefinition
        
        timezone 'Africa/Kinshasa' do |tz|
          tz.offset :o0, 3672, 0, :LMT
          tz.offset :o1, 3600, 0, :WAT
          
          tz.transition 1897, 11, :o1, 965694983, 400
        end
      end
    end
  end
end
