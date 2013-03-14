module TZInfo
  module Definitions
    module America
      module Jamaica
        include TimezoneDefinition
        
        timezone 'America/Jamaica' do |tz|
          tz.offset :o0, -18432, 0, :LMT
          tz.offset :o1, -18432, 0, :KMT
          tz.offset :o2, -18000, 0, :EST
          tz.offset :o3, -18000, 3600, :EDT
          
          tz.transition 1890, 1, :o1, 361705307, 150
          tz.transition 1912, 2, :o2, 362915057, 150
          tz.transition 1974, 4, :o3, 136364400
          tz.transition 1974, 10, :o2, 152085600
          tz.transition 1975, 2, :o3, 162370800
          tz.transition 1975, 10, :o2, 183535200
          tz.transition 1976, 4, :o3, 199263600
          tz.transition 1976, 10, :o2, 215589600
          tz.transition 1977, 4, :o3, 230713200
          tz.transition 1977, 10, :o2, 247039200
          tz.transition 1978, 4, :o3, 262767600
          tz.transition 1978, 10, :o2, 278488800
          tz.transition 1979, 4, :o3, 294217200
          tz.transition 1979, 10, :o2, 309938400
          tz.transition 1980, 4, :o3, 325666800
          tz.transition 1980, 10, :o2, 341388000
          tz.transition 1981, 4, :o3, 357116400
          tz.transition 1981, 10, :o2, 372837600
          tz.transition 1982, 4, :o3, 388566000
          tz.transition 1982, 10, :o2, 404892000
          tz.transition 1983, 4, :o3, 420015600
          tz.transition 1983, 10, :o2, 436341600
        end
      end
    end
  end
end
