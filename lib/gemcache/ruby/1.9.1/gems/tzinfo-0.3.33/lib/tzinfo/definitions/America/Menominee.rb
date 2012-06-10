module TZInfo
  module Definitions
    module America
      module Menominee
        include TimezoneDefinition
        
        timezone 'America/Menominee' do |tz|
          tz.offset :o0, -21027, 0, :LMT
          tz.offset :o1, -21600, 0, :CST
          tz.offset :o2, -21600, 3600, :CDT
          tz.offset :o3, -21600, 3600, :CWT
          tz.offset :o4, -21600, 3600, :CPT
          tz.offset :o5, -18000, 0, :EST
          
          tz.transition 1885, 9, :o1, 69402333409, 28800
          tz.transition 1918, 3, :o2, 14530103, 6
          tz.transition 1918, 10, :o1, 58125451, 24
          tz.transition 1919, 3, :o2, 14532287, 6
          tz.transition 1919, 10, :o1, 58134187, 24
          tz.transition 1942, 2, :o3, 14582399, 6
          tz.transition 1945, 8, :o4, 58360379, 24
          tz.transition 1945, 9, :o1, 58361491, 24
          tz.transition 1946, 4, :o2, 14591633, 6
          tz.transition 1946, 9, :o1, 58370227, 24
          tz.transition 1966, 4, :o2, 14635439, 6
          tz.transition 1966, 10, :o1, 58546291, 24
          tz.transition 1969, 4, :o5, 14642033, 6
          tz.transition 1973, 4, :o2, 104914800
          tz.transition 1973, 10, :o1, 120639600
          tz.transition 1974, 1, :o2, 126691200
          tz.transition 1974, 10, :o1, 152089200
          tz.transition 1975, 2, :o2, 162374400
          tz.transition 1975, 10, :o1, 183538800
          tz.transition 1976, 4, :o2, 199267200
          tz.transition 1976, 10, :o1, 215593200
          tz.transition 1977, 4, :o2, 230716800
          tz.transition 1977, 10, :o1, 247042800
          tz.transition 1978, 4, :o2, 262771200
          tz.transition 1978, 10, :o1, 278492400
          tz.transition 1979, 4, :o2, 294220800
          tz.transition 1979, 10, :o1, 309942000
          tz.transition 1980, 4, :o2, 325670400
          tz.transition 1980, 10, :o1, 341391600
          tz.transition 1981, 4, :o2, 357120000
          tz.transition 1981, 10, :o1, 372841200
          tz.transition 1982, 4, :o2, 388569600
          tz.transition 1982, 10, :o1, 404895600
          tz.transition 1983, 4, :o2, 420019200
          tz.transition 1983, 10, :o1, 436345200
          tz.transition 1984, 4, :o2, 452073600
          tz.transition 1984, 10, :o1, 467794800
          tz.transition 1985, 4, :o2, 483523200
          tz.transition 1985, 10, :o1, 499244400
          tz.transition 1986, 4, :o2, 514972800
          tz.transition 1986, 10, :o1, 530694000
          tz.transition 1987, 4, :o2, 544608000
          tz.transition 1987, 10, :o1, 562143600
          tz.transition 1988, 4, :o2, 576057600
          tz.transition 1988, 10, :o1, 594198000
          tz.transition 1989, 4, :o2, 607507200
          tz.transition 1989, 10, :o1, 625647600
          tz.transition 1990, 4, :o2, 638956800
          tz.transition 1990, 10, :o1, 657097200
          tz.transition 1991, 4, :o2, 671011200
          tz.transition 1991, 10, :o1, 688546800
          tz.transition 1992, 4, :o2, 702460800
          tz.transition 1992, 10, :o1, 719996400
          tz.transition 1993, 4, :o2, 733910400
          tz.transition 1993, 10, :o1, 752050800
          tz.transition 1994, 4, :o2, 765360000
          tz.transition 1994, 10, :o1, 783500400
          tz.transition 1995, 4, :o2, 796809600
          tz.transition 1995, 10, :o1, 814950000
          tz.transition 1996, 4, :o2, 828864000
          tz.transition 1996, 10, :o1, 846399600
          tz.transition 1997, 4, :o2, 860313600
          tz.transition 1997, 10, :o1, 877849200
          tz.transition 1998, 4, :o2, 891763200
          tz.transition 1998, 10, :o1, 909298800
          tz.transition 1999, 4, :o2, 923212800
          tz.transition 1999, 10, :o1, 941353200
          tz.transition 2000, 4, :o2, 954662400
          tz.transition 2000, 10, :o1, 972802800
          tz.transition 2001, 4, :o2, 986112000
          tz.transition 2001, 10, :o1, 1004252400
          tz.transition 2002, 4, :o2, 1018166400
          tz.transition 2002, 10, :o1, 1035702000
          tz.transition 2003, 4, :o2, 1049616000
          tz.transition 2003, 10, :o1, 1067151600
          tz.transition 2004, 4, :o2, 1081065600
          tz.transition 2004, 10, :o1, 1099206000
          tz.transition 2005, 4, :o2, 1112515200
          tz.transition 2005, 10, :o1, 1130655600
          tz.transition 2006, 4, :o2, 1143964800
          tz.transition 2006, 10, :o1, 1162105200
          tz.transition 2007, 3, :o2, 1173600000
          tz.transition 2007, 11, :o1, 1194159600
          tz.transition 2008, 3, :o2, 1205049600
          tz.transition 2008, 11, :o1, 1225609200
          tz.transition 2009, 3, :o2, 1236499200
          tz.transition 2009, 11, :o1, 1257058800
          tz.transition 2010, 3, :o2, 1268553600
          tz.transition 2010, 11, :o1, 1289113200
          tz.transition 2011, 3, :o2, 1300003200
          tz.transition 2011, 11, :o1, 1320562800
          tz.transition 2012, 3, :o2, 1331452800
          tz.transition 2012, 11, :o1, 1352012400
          tz.transition 2013, 3, :o2, 1362902400
          tz.transition 2013, 11, :o1, 1383462000
          tz.transition 2014, 3, :o2, 1394352000
          tz.transition 2014, 11, :o1, 1414911600
          tz.transition 2015, 3, :o2, 1425801600
          tz.transition 2015, 11, :o1, 1446361200
          tz.transition 2016, 3, :o2, 1457856000
          tz.transition 2016, 11, :o1, 1478415600
          tz.transition 2017, 3, :o2, 1489305600
          tz.transition 2017, 11, :o1, 1509865200
          tz.transition 2018, 3, :o2, 1520755200
          tz.transition 2018, 11, :o1, 1541314800
          tz.transition 2019, 3, :o2, 1552204800
          tz.transition 2019, 11, :o1, 1572764400
          tz.transition 2020, 3, :o2, 1583654400
          tz.transition 2020, 11, :o1, 1604214000
          tz.transition 2021, 3, :o2, 1615708800
          tz.transition 2021, 11, :o1, 1636268400
          tz.transition 2022, 3, :o2, 1647158400
          tz.transition 2022, 11, :o1, 1667718000
          tz.transition 2023, 3, :o2, 1678608000
          tz.transition 2023, 11, :o1, 1699167600
          tz.transition 2024, 3, :o2, 1710057600
          tz.transition 2024, 11, :o1, 1730617200
          tz.transition 2025, 3, :o2, 1741507200
          tz.transition 2025, 11, :o1, 1762066800
          tz.transition 2026, 3, :o2, 1772956800
          tz.transition 2026, 11, :o1, 1793516400
          tz.transition 2027, 3, :o2, 1805011200
          tz.transition 2027, 11, :o1, 1825570800
          tz.transition 2028, 3, :o2, 1836460800
          tz.transition 2028, 11, :o1, 1857020400
          tz.transition 2029, 3, :o2, 1867910400
          tz.transition 2029, 11, :o1, 1888470000
          tz.transition 2030, 3, :o2, 1899360000
          tz.transition 2030, 11, :o1, 1919919600
          tz.transition 2031, 3, :o2, 1930809600
          tz.transition 2031, 11, :o1, 1951369200
          tz.transition 2032, 3, :o2, 1962864000
          tz.transition 2032, 11, :o1, 1983423600
          tz.transition 2033, 3, :o2, 1994313600
          tz.transition 2033, 11, :o1, 2014873200
          tz.transition 2034, 3, :o2, 2025763200
          tz.transition 2034, 11, :o1, 2046322800
          tz.transition 2035, 3, :o2, 2057212800
          tz.transition 2035, 11, :o1, 2077772400
          tz.transition 2036, 3, :o2, 2088662400
          tz.transition 2036, 11, :o1, 2109222000
          tz.transition 2037, 3, :o2, 2120112000
          tz.transition 2037, 11, :o1, 2140671600
          tz.transition 2038, 3, :o2, 14792981, 6
          tz.transition 2038, 11, :o1, 59177635, 24
          tz.transition 2039, 3, :o2, 14795165, 6
          tz.transition 2039, 11, :o1, 59186371, 24
          tz.transition 2040, 3, :o2, 14797349, 6
          tz.transition 2040, 11, :o1, 59195107, 24
          tz.transition 2041, 3, :o2, 14799533, 6
          tz.transition 2041, 11, :o1, 59203843, 24
          tz.transition 2042, 3, :o2, 14801717, 6
          tz.transition 2042, 11, :o1, 59212579, 24
          tz.transition 2043, 3, :o2, 14803901, 6
          tz.transition 2043, 11, :o1, 59221315, 24
          tz.transition 2044, 3, :o2, 14806127, 6
          tz.transition 2044, 11, :o1, 59230219, 24
          tz.transition 2045, 3, :o2, 14808311, 6
          tz.transition 2045, 11, :o1, 59238955, 24
          tz.transition 2046, 3, :o2, 14810495, 6
          tz.transition 2046, 11, :o1, 59247691, 24
          tz.transition 2047, 3, :o2, 14812679, 6
          tz.transition 2047, 11, :o1, 59256427, 24
          tz.transition 2048, 3, :o2, 14814863, 6
          tz.transition 2048, 11, :o1, 59265163, 24
          tz.transition 2049, 3, :o2, 14817089, 6
          tz.transition 2049, 11, :o1, 59274067, 24
          tz.transition 2050, 3, :o2, 14819273, 6
          tz.transition 2050, 11, :o1, 59282803, 24
        end
      end
    end
  end
end
