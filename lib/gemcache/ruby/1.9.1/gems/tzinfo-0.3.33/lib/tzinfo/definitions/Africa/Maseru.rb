module TZInfo
  module Definitions
    module Africa
      module Maseru
        include TimezoneDefinition
        
        timezone 'Africa/Maseru' do |tz|
          tz.offset :o0, 6600, 0, :LMT
          tz.offset :o1, 7200, 0, :SAST
          tz.offset :o2, 7200, 3600, :SAST
          
          tz.transition 1903, 2, :o1, 347929117, 144
          tz.transition 1943, 9, :o2, 4861973, 2
          tz.transition 1944, 3, :o1, 58348043, 24
        end
      end
    end
  end
end
