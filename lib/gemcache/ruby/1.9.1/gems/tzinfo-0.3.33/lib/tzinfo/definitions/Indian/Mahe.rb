module TZInfo
  module Definitions
    module Indian
      module Mahe
        include TimezoneDefinition
        
        timezone 'Indian/Mahe' do |tz|
          tz.offset :o0, 13308, 0, :LMT
          tz.offset :o1, 14400, 0, :SCT
          
          tz.transition 1906, 5, :o1, 17405008891, 7200
        end
      end
    end
  end
end
