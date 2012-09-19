module TZInfo
  module Definitions
    module America
      module Ojinaga
        include TimezoneDefinition
        
        timezone 'America/Ojinaga' do |tz|
          tz.offset :o0, -25060, 0, :LMT
          tz.offset :o1, -25200, 0, :MST
          tz.offset :o2, -21600, 0, :CST
          tz.offset :o3, -21600, 3600, :CDT
          tz.offset :o4, -25200, 3600, :MDT
          
          tz.transition 1922, 1, :o1, 58153339, 24
          tz.transition 1927, 6, :o2, 9700171, 4
          tz.transition 1930, 11, :o1, 9705183, 4
          tz.transition 1931, 5, :o2, 9705855, 4
          tz.transition 1931, 10, :o1, 9706463, 4
          tz.transition 1932, 4, :o2, 58243171, 24
          tz.transition 1996, 4, :o3, 828864000
          tz.transition 1996, 10, :o2, 846399600
          tz.transition 1997, 4, :o3, 860313600
          tz.transition 1997, 10, :o2, 877849200
          tz.transition 1998, 4, :o4, 891766800
          tz.transition 1998, 10, :o1, 909302400
          tz.transition 1999, 4, :o4, 923216400
          tz.transition 1999, 10, :o1, 941356800
          tz.transition 2000, 4, :o4, 954666000
          tz.transition 2000, 10, :o1, 972806400
          tz.transition 2001, 5, :o4, 989139600
          tz.transition 2001, 9, :o1, 1001836800
          tz.transition 2002, 4, :o4, 1018170000
          tz.transition 2002, 10, :o1, 1035705600
          tz.transition 2003, 4, :o4, 1049619600
          tz.transition 2003, 10, :o1, 1067155200
          tz.transition 2004, 4, :o4, 1081069200
          tz.transition 2004, 10, :o1, 1099209600
          tz.transition 2005, 4, :o4, 1112518800
          tz.transition 2005, 10, :o1, 1130659200
          tz.transition 2006, 4, :o4, 1143968400
          tz.transition 2006, 10, :o1, 1162108800
          tz.transition 2007, 4, :o4, 1175418000
          tz.transition 2007, 10, :o1, 1193558400
          tz.transition 2008, 4, :o4, 1207472400
          tz.transition 2008, 10, :o1, 1225008000
          tz.transition 2009, 4, :o4, 1238922000
          tz.transition 2009, 10, :o1, 1256457600
          tz.transition 2010, 3, :o4, 1268557200
          tz.transition 2010, 11, :o1, 1289116800
          tz.transition 2011, 3, :o4, 1300006800
          tz.transition 2011, 11, :o1, 1320566400
          tz.transition 2012, 3, :o4, 1331456400
          tz.transition 2012, 11, :o1, 1352016000
          tz.transition 2013, 3, :o4, 1362906000
          tz.transition 2013, 11, :o1, 1383465600
          tz.transition 2014, 3, :o4, 1394355600
          tz.transition 2014, 11, :o1, 1414915200
          tz.transition 2015, 3, :o4, 1425805200
          tz.transition 2015, 11, :o1, 1446364800
          tz.transition 2016, 3, :o4, 1457859600
          tz.transition 2016, 11, :o1, 1478419200
          tz.transition 2017, 3, :o4, 1489309200
          tz.transition 2017, 11, :o1, 1509868800
          tz.transition 2018, 3, :o4, 1520758800
          tz.transition 2018, 11, :o1, 1541318400
          tz.transition 2019, 3, :o4, 1552208400
          tz.transition 2019, 11, :o1, 1572768000
          tz.transition 2020, 3, :o4, 1583658000
          tz.transition 2020, 11, :o1, 1604217600
          tz.transition 2021, 3, :o4, 1615712400
          tz.transition 2021, 11, :o1, 1636272000
          tz.transition 2022, 3, :o4, 1647162000
          tz.transition 2022, 11, :o1, 1667721600
          tz.transition 2023, 3, :o4, 1678611600
          tz.transition 2023, 11, :o1, 1699171200
          tz.transition 2024, 3, :o4, 1710061200
          tz.transition 2024, 11, :o1, 1730620800
          tz.transition 2025, 3, :o4, 1741510800
          tz.transition 2025, 11, :o1, 1762070400
          tz.transition 2026, 3, :o4, 1772960400
          tz.transition 2026, 11, :o1, 1793520000
          tz.transition 2027, 3, :o4, 1805014800
          tz.transition 2027, 11, :o1, 1825574400
          tz.transition 2028, 3, :o4, 1836464400
          tz.transition 2028, 11, :o1, 1857024000
          tz.transition 2029, 3, :o4, 1867914000
          tz.transition 2029, 11, :o1, 1888473600
          tz.transition 2030, 3, :o4, 1899363600
          tz.transition 2030, 11, :o1, 1919923200
          tz.transition 2031, 3, :o4, 1930813200
          tz.transition 2031, 11, :o1, 1951372800
          tz.transition 2032, 3, :o4, 1962867600
          tz.transition 2032, 11, :o1, 1983427200
          tz.transition 2033, 3, :o4, 1994317200
          tz.transition 2033, 11, :o1, 2014876800
          tz.transition 2034, 3, :o4, 2025766800
          tz.transition 2034, 11, :o1, 2046326400
          tz.transition 2035, 3, :o4, 2057216400
          tz.transition 2035, 11, :o1, 2077776000
          tz.transition 2036, 3, :o4, 2088666000
          tz.transition 2036, 11, :o1, 2109225600
          tz.transition 2037, 3, :o4, 2120115600
          tz.transition 2037, 11, :o1, 2140675200
          tz.transition 2038, 3, :o4, 19723975, 8
          tz.transition 2038, 11, :o1, 14794409, 6
          tz.transition 2039, 3, :o4, 19726887, 8
          tz.transition 2039, 11, :o1, 14796593, 6
          tz.transition 2040, 3, :o4, 19729799, 8
          tz.transition 2040, 11, :o1, 14798777, 6
          tz.transition 2041, 3, :o4, 19732711, 8
          tz.transition 2041, 11, :o1, 14800961, 6
          tz.transition 2042, 3, :o4, 19735623, 8
          tz.transition 2042, 11, :o1, 14803145, 6
          tz.transition 2043, 3, :o4, 19738535, 8
          tz.transition 2043, 11, :o1, 14805329, 6
          tz.transition 2044, 3, :o4, 19741503, 8
          tz.transition 2044, 11, :o1, 14807555, 6
          tz.transition 2045, 3, :o4, 19744415, 8
          tz.transition 2045, 11, :o1, 14809739, 6
          tz.transition 2046, 3, :o4, 19747327, 8
          tz.transition 2046, 11, :o1, 14811923, 6
          tz.transition 2047, 3, :o4, 19750239, 8
          tz.transition 2047, 11, :o1, 14814107, 6
          tz.transition 2048, 3, :o4, 19753151, 8
          tz.transition 2048, 11, :o1, 14816291, 6
          tz.transition 2049, 3, :o4, 19756119, 8
          tz.transition 2049, 11, :o1, 14818517, 6
          tz.transition 2050, 3, :o4, 19759031, 8
          tz.transition 2050, 11, :o1, 14820701, 6
        end
      end
    end
  end
end
