module TZInfo
  module Definitions
    module America
      module Bahia_Banderas
        include TimezoneDefinition
        
        timezone 'America/Bahia_Banderas' do |tz|
          tz.offset :o0, -25260, 0, :LMT
          tz.offset :o1, -25200, 0, :MST
          tz.offset :o2, -21600, 0, :CST
          tz.offset :o3, -28800, 0, :PST
          tz.offset :o4, -25200, 3600, :MDT
          tz.offset :o5, -21600, 3600, :CDT
          
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
          tz.transition 2010, 4, :o5, 1270371600
          tz.transition 2010, 10, :o2, 1288508400
          tz.transition 2011, 4, :o5, 1301817600
          tz.transition 2011, 10, :o2, 1319958000
          tz.transition 2012, 4, :o5, 1333267200
          tz.transition 2012, 10, :o2, 1351407600
          tz.transition 2013, 4, :o5, 1365321600
          tz.transition 2013, 10, :o2, 1382857200
          tz.transition 2014, 4, :o5, 1396771200
          tz.transition 2014, 10, :o2, 1414306800
          tz.transition 2015, 4, :o5, 1428220800
          tz.transition 2015, 10, :o2, 1445756400
          tz.transition 2016, 4, :o5, 1459670400
          tz.transition 2016, 10, :o2, 1477810800
          tz.transition 2017, 4, :o5, 1491120000
          tz.transition 2017, 10, :o2, 1509260400
          tz.transition 2018, 4, :o5, 1522569600
          tz.transition 2018, 10, :o2, 1540710000
          tz.transition 2019, 4, :o5, 1554624000
          tz.transition 2019, 10, :o2, 1572159600
          tz.transition 2020, 4, :o5, 1586073600
          tz.transition 2020, 10, :o2, 1603609200
          tz.transition 2021, 4, :o5, 1617523200
          tz.transition 2021, 10, :o2, 1635663600
          tz.transition 2022, 4, :o5, 1648972800
          tz.transition 2022, 10, :o2, 1667113200
          tz.transition 2023, 4, :o5, 1680422400
          tz.transition 2023, 10, :o2, 1698562800
          tz.transition 2024, 4, :o5, 1712476800
          tz.transition 2024, 10, :o2, 1730012400
          tz.transition 2025, 4, :o5, 1743926400
          tz.transition 2025, 10, :o2, 1761462000
          tz.transition 2026, 4, :o5, 1775376000
          tz.transition 2026, 10, :o2, 1792911600
          tz.transition 2027, 4, :o5, 1806825600
          tz.transition 2027, 10, :o2, 1824966000
          tz.transition 2028, 4, :o5, 1838275200
          tz.transition 2028, 10, :o2, 1856415600
          tz.transition 2029, 4, :o5, 1869724800
          tz.transition 2029, 10, :o2, 1887865200
          tz.transition 2030, 4, :o5, 1901779200
          tz.transition 2030, 10, :o2, 1919314800
          tz.transition 2031, 4, :o5, 1933228800
          tz.transition 2031, 10, :o2, 1950764400
          tz.transition 2032, 4, :o5, 1964678400
          tz.transition 2032, 10, :o2, 1982818800
          tz.transition 2033, 4, :o5, 1996128000
          tz.transition 2033, 10, :o2, 2014268400
          tz.transition 2034, 4, :o5, 2027577600
          tz.transition 2034, 10, :o2, 2045718000
          tz.transition 2035, 4, :o5, 2059027200
          tz.transition 2035, 10, :o2, 2077167600
          tz.transition 2036, 4, :o5, 2091081600
          tz.transition 2036, 10, :o2, 2108617200
          tz.transition 2037, 4, :o5, 2122531200
          tz.transition 2037, 10, :o2, 2140066800
          tz.transition 2038, 4, :o5, 14793107, 6
          tz.transition 2038, 10, :o2, 59177467, 24
          tz.transition 2039, 4, :o5, 14795291, 6
          tz.transition 2039, 10, :o2, 59186203, 24
          tz.transition 2040, 4, :o5, 14797475, 6
          tz.transition 2040, 10, :o2, 59194939, 24
          tz.transition 2041, 4, :o5, 14799701, 6
          tz.transition 2041, 10, :o2, 59203675, 24
          tz.transition 2042, 4, :o5, 14801885, 6
          tz.transition 2042, 10, :o2, 59212411, 24
          tz.transition 2043, 4, :o5, 14804069, 6
          tz.transition 2043, 10, :o2, 59221147, 24
          tz.transition 2044, 4, :o5, 14806253, 6
          tz.transition 2044, 10, :o2, 59230051, 24
          tz.transition 2045, 4, :o5, 14808437, 6
          tz.transition 2045, 10, :o2, 59238787, 24
          tz.transition 2046, 4, :o5, 14810621, 6
          tz.transition 2046, 10, :o2, 59247523, 24
          tz.transition 2047, 4, :o5, 14812847, 6
          tz.transition 2047, 10, :o2, 59256259, 24
          tz.transition 2048, 4, :o5, 14815031, 6
          tz.transition 2048, 10, :o2, 59264995, 24
          tz.transition 2049, 4, :o5, 14817215, 6
          tz.transition 2049, 10, :o2, 59273899, 24
          tz.transition 2050, 4, :o5, 14819399, 6
          tz.transition 2050, 10, :o2, 59282635, 24
        end
      end
    end
  end
end
