module TZInfo
  module Definitions
    module America
      module Hermosillo
        include TimezoneDefinition
        
        timezone 'America/Hermosillo' do |tz|
          tz.offset :o0, -26632, 0, :LMT
          tz.offset :o1, -25200, 0, :MST
          tz.offset :o2, -21600, 0, :CST
          tz.offset :o3, -28800, 0, :PST
          tz.offset :o4, -25200, 3600, :MDT
          
          tz.transition 1922, 1, :o1, 58153339, 24
          tz.transition 1927, 6, :o2, 9700171, 4
          tz.transition 1930, 11, :o1, 9705183, 4
          tz.transition 1931, 5, :o2, 9705855, 4
          tz.transition 1931, 10, :o1, 9706463, 4
          tz.transition 1932, 4, :o2, 58243171, 24
          tz.transition 1942, 4, :o1, 9721895, 4
          tz.transition 1949, 1, :o3, 58390339, 24
          tz.transition 1970, 1, :o1, 28800
          tz.transition 1996, 4, :o4, 828867600
          tz.transition 1996, 10, :o1, 846403200
          tz.transition 1997, 4, :o4, 860317200
          tz.transition 1997, 10, :o1, 877852800
          tz.transition 1998, 4, :o4, 891766800
          tz.transition 1998, 10, :o1, 909302400
        end
      end
    end
  end
end
