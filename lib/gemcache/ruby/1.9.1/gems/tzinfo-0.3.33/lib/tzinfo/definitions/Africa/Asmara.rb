module TZInfo
  module Definitions
    module Africa
      module Asmara
        include TimezoneDefinition
        
        timezone 'Africa/Asmara' do |tz|
          tz.offset :o0, 9332, 0, :LMT
          tz.offset :o1, 9332, 0, :AMT
          tz.offset :o2, 9320, 0, :ADMT
          tz.offset :o3, 10800, 0, :EAT
          
          tz.transition 1869, 12, :o1, 51927769267, 21600
          tz.transition 1889, 12, :o2, 52085557267, 21600
          tz.transition 1936, 5, :o3, 5245113727, 2160
        end
      end
    end
  end
end
