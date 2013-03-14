module TZInfo
  module Definitions
    module Pacific
      module Enderbury
        include TimezoneDefinition
        
        timezone 'Pacific/Enderbury' do |tz|
          tz.offset :o0, -41060, 0, :LMT
          tz.offset :o1, -43200, 0, :PHOT
          tz.offset :o2, -39600, 0, :PHOT
          tz.offset :o3, 46800, 0, :PHOT
          
          tz.transition 1901, 1, :o1, 10434467413, 4320
          tz.transition 1979, 10, :o2, 307627200
          tz.transition 1995, 1, :o3, 788958000
        end
      end
    end
  end
end
