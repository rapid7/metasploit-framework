module TZInfo
  module Definitions
    module Africa
      module Bangui
        include TimezoneDefinition
        
        timezone 'Africa/Bangui' do |tz|
          tz.offset :o0, 4460, 0, :LMT
          tz.offset :o1, 3600, 0, :WAT
          
          tz.transition 1911, 12, :o1, 10451818577, 4320
        end
      end
    end
  end
end
