module TZInfo
  module Definitions
    module Pacific
      module Funafuti
        include TimezoneDefinition
        
        timezone 'Pacific/Funafuti' do |tz|
          tz.offset :o0, 43012, 0, :LMT
          tz.offset :o1, 43200, 0, :TVT
          
          tz.transition 1900, 12, :o1, 52172316047, 21600
        end
      end
    end
  end
end
