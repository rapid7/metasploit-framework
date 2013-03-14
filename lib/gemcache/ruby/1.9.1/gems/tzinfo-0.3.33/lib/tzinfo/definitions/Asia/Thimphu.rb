module TZInfo
  module Definitions
    module Asia
      module Thimphu
        include TimezoneDefinition
        
        timezone 'Asia/Thimphu' do |tz|
          tz.offset :o0, 21516, 0, :LMT
          tz.offset :o1, 19800, 0, :IST
          tz.offset :o2, 21600, 0, :BTT
          
          tz.transition 1947, 8, :o1, 17513368207, 7200
          tz.transition 1987, 9, :o2, 560025000
        end
      end
    end
  end
end
