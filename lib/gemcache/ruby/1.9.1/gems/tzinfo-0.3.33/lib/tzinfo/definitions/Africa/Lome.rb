module TZInfo
  module Definitions
    module Africa
      module Lome
        include TimezoneDefinition
        
        timezone 'Africa/Lome' do |tz|
          tz.offset :o0, 292, 0, :LMT
          tz.offset :o1, 0, 0, :GMT
          
          tz.transition 1892, 12, :o1, 52109233127, 21600
        end
      end
    end
  end
end
