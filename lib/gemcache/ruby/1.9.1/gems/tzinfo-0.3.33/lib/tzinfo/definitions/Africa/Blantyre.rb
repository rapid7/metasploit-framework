module TZInfo
  module Definitions
    module Africa
      module Blantyre
        include TimezoneDefinition
        
        timezone 'Africa/Blantyre' do |tz|
          tz.offset :o0, 8400, 0, :LMT
          tz.offset :o1, 7200, 0, :CAT
          
          tz.transition 1903, 2, :o1, 173964557, 72
        end
      end
    end
  end
end
