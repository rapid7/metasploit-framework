module TZInfo
  module Definitions
    module Pacific
      module Kiritimati
        include TimezoneDefinition
        
        timezone 'Pacific/Kiritimati' do |tz|
          tz.offset :o0, -37760, 0, :LMT
          tz.offset :o1, -38400, 0, :LINT
          tz.offset :o2, -36000, 0, :LINT
          tz.offset :o3, 50400, 0, :LINT
          
          tz.transition 1901, 1, :o1, 652154203, 270
          tz.transition 1979, 10, :o2, 307622400
          tz.transition 1995, 1, :o3, 788954400
        end
      end
    end
  end
end
