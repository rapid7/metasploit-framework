module TZInfo
  module Definitions
    module Asia
      module Pyongyang
        include TimezoneDefinition
        
        timezone 'Asia/Pyongyang' do |tz|
          tz.offset :o0, 30180, 0, :LMT
          tz.offset :o1, 30600, 0, :KST
          tz.offset :o2, 32400, 0, :KST
          tz.offset :o3, 28800, 0, :KST
          
          tz.transition 1889, 12, :o1, 3472370137, 1440
          tz.transition 1904, 11, :o2, 116007127, 48
          tz.transition 1927, 12, :o1, 19401969, 8
          tz.transition 1931, 12, :o2, 116481943, 48
          tz.transition 1954, 3, :o3, 19478577, 8
          tz.transition 1961, 8, :o2, 14625127, 6
        end
      end
    end
  end
end
