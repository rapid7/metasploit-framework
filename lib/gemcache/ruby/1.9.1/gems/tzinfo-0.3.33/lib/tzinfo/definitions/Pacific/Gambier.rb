module TZInfo
  module Definitions
    module Pacific
      module Gambier
        include TimezoneDefinition
        
        timezone 'Pacific/Gambier' do |tz|
          tz.offset :o0, -32388, 0, :LMT
          tz.offset :o1, -32400, 0, :GAMT
          
          tz.transition 1912, 10, :o1, 17421673499, 7200
        end
      end
    end
  end
end
