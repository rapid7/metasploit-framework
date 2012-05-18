module TZInfo
  module Definitions
    module Asia
      module Macau
        include TimezoneDefinition
        
        timezone 'Asia/Macau' do |tz|
          tz.offset :o0, 27260, 0, :LMT
          tz.offset :o1, 28800, 0, :MOT
          tz.offset :o2, 28800, 3600, :MOST
          tz.offset :o3, 28800, 0, :CST
          
          tz.transition 1911, 12, :o1, 10451817437, 4320
          tz.transition 1961, 3, :o2, 38998037, 16
          tz.transition 1961, 11, :o1, 117005197, 48
          tz.transition 1962, 3, :o2, 39003861, 16
          tz.transition 1962, 11, :o1, 117022669, 48
          tz.transition 1963, 3, :o2, 14628631, 6
          tz.transition 1963, 11, :o1, 117040141, 48
          tz.transition 1964, 3, :o2, 39015621, 16
          tz.transition 1964, 10, :o1, 117057613, 48
          tz.transition 1965, 3, :o2, 14633041, 6
          tz.transition 1965, 10, :o1, 19512513, 8
          tz.transition 1966, 4, :o2, 39027717, 16
          tz.transition 1966, 10, :o1, 117091885, 48
          tz.transition 1967, 4, :o2, 39033541, 16
          tz.transition 1967, 10, :o1, 117109693, 48
          tz.transition 1968, 4, :o2, 39039477, 16
          tz.transition 1968, 10, :o1, 117127165, 48
          tz.transition 1969, 4, :o2, 39045301, 16
          tz.transition 1969, 10, :o1, 117144637, 48
          tz.transition 1970, 4, :o2, 9315000
          tz.transition 1970, 10, :o1, 25036200
          tz.transition 1971, 4, :o2, 40764600
          tz.transition 1971, 10, :o1, 56485800
          tz.transition 1972, 4, :o2, 72201600
          tz.transition 1972, 10, :o1, 87922800
          tz.transition 1973, 4, :o2, 103651200
          tz.transition 1973, 10, :o1, 119977200
          tz.transition 1974, 4, :o2, 135705600
          tz.transition 1974, 10, :o1, 151439400
          tz.transition 1975, 4, :o2, 167167800
          tz.transition 1975, 10, :o1, 182889000
          tz.transition 1976, 4, :o2, 198617400
          tz.transition 1976, 10, :o1, 214338600
          tz.transition 1977, 4, :o2, 230067000
          tz.transition 1977, 10, :o1, 245788200
          tz.transition 1978, 4, :o2, 261504000
          tz.transition 1978, 10, :o1, 277225200
          tz.transition 1979, 4, :o2, 292953600
          tz.transition 1979, 10, :o1, 309279600
          tz.transition 1980, 4, :o2, 325008000
          tz.transition 1980, 10, :o1, 340729200
          tz.transition 1999, 12, :o3, 945619200
        end
      end
    end
  end
end
