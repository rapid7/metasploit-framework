module TZInfo
  module Definitions
    module America
      module Porto_Velho
        include TimezoneDefinition
        
        timezone 'America/Porto_Velho' do |tz|
          tz.offset :o0, -15336, 0, :LMT
          tz.offset :o1, -14400, 0, :AMT
          tz.offset :o2, -14400, 3600, :AMST
          
          tz.transition 1914, 1, :o1, 968053471, 400
          tz.transition 1931, 10, :o2, 19412945, 8
          tz.transition 1932, 4, :o1, 19414389, 8
          tz.transition 1932, 10, :o2, 7280951, 3
          tz.transition 1933, 4, :o1, 19417309, 8
          tz.transition 1949, 12, :o2, 7299755, 3
          tz.transition 1950, 4, :o1, 7300163, 3
          tz.transition 1950, 12, :o2, 7300850, 3
          tz.transition 1951, 4, :o1, 19469901, 8
          tz.transition 1951, 12, :o2, 7301945, 3
          tz.transition 1952, 4, :o1, 19472829, 8
          tz.transition 1952, 12, :o2, 7303043, 3
          tz.transition 1953, 3, :o1, 19475501, 8
          tz.transition 1963, 12, :o2, 7315118, 3
          tz.transition 1964, 3, :o1, 19507645, 8
          tz.transition 1965, 1, :o2, 7316375, 3
          tz.transition 1965, 3, :o1, 19510805, 8
          tz.transition 1965, 12, :o2, 7317287, 3
          tz.transition 1966, 3, :o1, 19513485, 8
          tz.transition 1966, 11, :o2, 7318292, 3
          tz.transition 1967, 3, :o1, 19516405, 8
          tz.transition 1967, 11, :o2, 7319387, 3
          tz.transition 1968, 3, :o1, 19519333, 8
          tz.transition 1985, 11, :o2, 499752000
          tz.transition 1986, 3, :o1, 511239600
          tz.transition 1986, 10, :o2, 530596800
          tz.transition 1987, 2, :o1, 540270000
          tz.transition 1987, 10, :o2, 562132800
          tz.transition 1988, 2, :o1, 571201200
        end
      end
    end
  end
end
