module TZInfo
  module Definitions
    module Pacific
      module Pitcairn
        include TimezoneDefinition
        
        timezone 'Pacific/Pitcairn' do |tz|
          tz.offset :o0, -31220, 0, :LMT
          tz.offset :o1, -30600, 0, :PNT
          tz.offset :o2, -28800, 0, :PST
          
          tz.transition 1901, 1, :o1, 10434466921, 4320
          tz.transition 1998, 4, :o2, 893665800
        end
      end
    end
  end
end
