module TZInfo
  module Definitions
    module America
      module Eirunepe
        include TimezoneDefinition
        
        timezone 'America/Eirunepe' do |tz|
          tz.offset :o0, -16768, 0, :LMT
          tz.offset :o1, -18000, 0, :ACT
          tz.offset :o2, -18000, 3600, :ACST
          tz.offset :o3, -14400, 0, :AMT
          
          tz.transition 1914, 1, :o1, 3267180487, 1350
          tz.transition 1931, 10, :o2, 14559709, 6
          tz.transition 1932, 4, :o1, 7280396, 3
          tz.transition 1932, 10, :o2, 58247609, 24
          tz.transition 1933, 4, :o1, 7281491, 3
          tz.transition 1949, 12, :o2, 58398041, 24
          tz.transition 1950, 4, :o1, 58401305, 24
          tz.transition 1950, 12, :o2, 58406801, 24
          tz.transition 1951, 4, :o1, 7301213, 3
          tz.transition 1951, 12, :o2, 58415561, 24
          tz.transition 1952, 4, :o1, 7302311, 3
          tz.transition 1952, 12, :o2, 58424345, 24
          tz.transition 1953, 3, :o1, 7303313, 3
          tz.transition 1963, 12, :o2, 58520945, 24
          tz.transition 1964, 3, :o1, 7315367, 3
          tz.transition 1965, 1, :o2, 58531001, 24
          tz.transition 1965, 3, :o1, 7316552, 3
          tz.transition 1965, 12, :o2, 58538297, 24
          tz.transition 1966, 3, :o1, 7317557, 3
          tz.transition 1966, 11, :o2, 58546337, 24
          tz.transition 1967, 3, :o1, 7318652, 3
          tz.transition 1967, 11, :o2, 58555097, 24
          tz.transition 1968, 3, :o1, 7319750, 3
          tz.transition 1985, 11, :o2, 499755600
          tz.transition 1986, 3, :o1, 511243200
          tz.transition 1986, 10, :o2, 530600400
          tz.transition 1987, 2, :o1, 540273600
          tz.transition 1987, 10, :o2, 562136400
          tz.transition 1988, 2, :o1, 571204800
          tz.transition 1993, 10, :o2, 750834000
          tz.transition 1994, 2, :o1, 761716800
          tz.transition 2008, 6, :o3, 1214283600
        end
      end
    end
  end
end
