module TZInfo
  module Definitions
    module Pacific
      module Niue
        include TimezoneDefinition
        
        timezone 'Pacific/Niue' do |tz|
          tz.offset :o0, -40780, 0, :LMT
          tz.offset :o1, -40800, 0, :NUT
          tz.offset :o2, -41400, 0, :NUT
          tz.offset :o3, -39600, 0, :NUT
          
          tz.transition 1901, 1, :o1, 10434467399, 4320
          tz.transition 1951, 1, :o2, 87611327, 36
          tz.transition 1978, 10, :o3, 276089400
        end
      end
    end
  end
end
