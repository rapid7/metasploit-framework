module TZInfo
  module Definitions
    module America
      module Paramaribo
        include TimezoneDefinition
        
        timezone 'America/Paramaribo' do |tz|
          tz.offset :o0, -13240, 0, :LMT
          tz.offset :o1, -13252, 0, :PMT
          tz.offset :o2, -13236, 0, :PMT
          tz.offset :o3, -12600, 0, :NEGT
          tz.offset :o4, -12600, 0, :SRT
          tz.offset :o5, -10800, 0, :SRT
          
          tz.transition 1911, 1, :o1, 5225121331, 2160
          tz.transition 1935, 1, :o2, 52440558913, 21600
          tz.transition 1945, 10, :o3, 17508453503, 7200
          tz.transition 1975, 11, :o4, 185686200
          tz.transition 1984, 10, :o5, 465449400
        end
      end
    end
  end
end
