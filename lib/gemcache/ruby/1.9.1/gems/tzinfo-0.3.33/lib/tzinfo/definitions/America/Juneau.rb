module TZInfo
  module Definitions
    module America
      module Juneau
        include TimezoneDefinition
        
        timezone 'America/Juneau' do |tz|
          tz.offset :o0, 54139, 0, :LMT
          tz.offset :o1, -32261, 0, :LMT
          tz.offset :o2, -28800, 0, :PST
          tz.offset :o3, -28800, 3600, :PWT
          tz.offset :o4, -28800, 3600, :PPT
          tz.offset :o5, -28800, 3600, :PDT
          tz.offset :o6, -32400, 3600, :YDT
          tz.offset :o7, -32400, 0, :YST
          tz.offset :o8, -32400, 0, :AKST
          tz.offset :o9, -32400, 3600, :AKDT
          
          tz.transition 1867, 10, :o1, 207641393861, 86400
          tz.transition 1900, 8, :o2, 208677805061, 86400
          tz.transition 1942, 2, :o3, 29164799, 12
          tz.transition 1945, 8, :o4, 58360379, 24
          tz.transition 1945, 9, :o2, 19453831, 8
          tz.transition 1969, 4, :o5, 29284067, 12
          tz.transition 1969, 10, :o2, 19524167, 8
          tz.transition 1970, 4, :o5, 9972000
          tz.transition 1970, 10, :o2, 25693200
          tz.transition 1971, 4, :o5, 41421600
          tz.transition 1971, 10, :o2, 57747600
          tz.transition 1972, 4, :o5, 73476000
          tz.transition 1972, 10, :o2, 89197200
          tz.transition 1973, 4, :o5, 104925600
          tz.transition 1973, 10, :o2, 120646800
          tz.transition 1974, 1, :o5, 126698400
          tz.transition 1974, 10, :o2, 152096400
          tz.transition 1975, 2, :o5, 162381600
          tz.transition 1975, 10, :o2, 183546000
          tz.transition 1976, 4, :o5, 199274400
          tz.transition 1976, 10, :o2, 215600400
          tz.transition 1977, 4, :o5, 230724000
          tz.transition 1977, 10, :o2, 247050000
          tz.transition 1978, 4, :o5, 262778400
          tz.transition 1978, 10, :o2, 278499600
          tz.transition 1979, 4, :o5, 294228000
          tz.transition 1979, 10, :o2, 309949200
          tz.transition 1980, 4, :o6, 325677600
          tz.transition 1980, 10, :o2, 341402400
          tz.transition 1981, 4, :o5, 357127200
          tz.transition 1981, 10, :o2, 372848400
          tz.transition 1982, 4, :o5, 388576800
          tz.transition 1982, 10, :o2, 404902800
          tz.transition 1983, 4, :o5, 420026400
          tz.transition 1983, 10, :o7, 436352400
          tz.transition 1983, 11, :o8, 439030800
          tz.transition 1984, 4, :o9, 452084400
          tz.transition 1984, 10, :o8, 467805600
          tz.transition 1985, 4, :o9, 483534000
          tz.transition 1985, 10, :o8, 499255200
          tz.transition 1986, 4, :o9, 514983600
          tz.transition 1986, 10, :o8, 530704800
          tz.transition 1987, 4, :o9, 544618800
          tz.transition 1987, 10, :o8, 562154400
          tz.transition 1988, 4, :o9, 576068400
          tz.transition 1988, 10, :o8, 594208800
          tz.transition 1989, 4, :o9, 607518000
          tz.transition 1989, 10, :o8, 625658400
          tz.transition 1990, 4, :o9, 638967600
          tz.transition 1990, 10, :o8, 657108000
          tz.transition 1991, 4, :o9, 671022000
          tz.transition 1991, 10, :o8, 688557600
          tz.transition 1992, 4, :o9, 702471600
          tz.transition 1992, 10, :o8, 720007200
          tz.transition 1993, 4, :o9, 733921200
          tz.transition 1993, 10, :o8, 752061600
          tz.transition 1994, 4, :o9, 765370800
          tz.transition 1994, 10, :o8, 783511200
          tz.transition 1995, 4, :o9, 796820400
          tz.transition 1995, 10, :o8, 814960800
          tz.transition 1996, 4, :o9, 828874800
          tz.transition 1996, 10, :o8, 846410400
          tz.transition 1997, 4, :o9, 860324400
          tz.transition 1997, 10, :o8, 877860000
          tz.transition 1998, 4, :o9, 891774000
          tz.transition 1998, 10, :o8, 909309600
          tz.transition 1999, 4, :o9, 923223600
          tz.transition 1999, 10, :o8, 941364000
          tz.transition 2000, 4, :o9, 954673200
          tz.transition 2000, 10, :o8, 972813600
          tz.transition 2001, 4, :o9, 986122800
          tz.transition 2001, 10, :o8, 1004263200
          tz.transition 2002, 4, :o9, 1018177200
          tz.transition 2002, 10, :o8, 1035712800
          tz.transition 2003, 4, :o9, 1049626800
          tz.transition 2003, 10, :o8, 1067162400
          tz.transition 2004, 4, :o9, 1081076400
          tz.transition 2004, 10, :o8, 1099216800
          tz.transition 2005, 4, :o9, 1112526000
          tz.transition 2005, 10, :o8, 1130666400
          tz.transition 2006, 4, :o9, 1143975600
          tz.transition 2006, 10, :o8, 1162116000
          tz.transition 2007, 3, :o9, 1173610800
          tz.transition 2007, 11, :o8, 1194170400
          tz.transition 2008, 3, :o9, 1205060400
          tz.transition 2008, 11, :o8, 1225620000
          tz.transition 2009, 3, :o9, 1236510000
          tz.transition 2009, 11, :o8, 1257069600
          tz.transition 2010, 3, :o9, 1268564400
          tz.transition 2010, 11, :o8, 1289124000
          tz.transition 2011, 3, :o9, 1300014000
          tz.transition 2011, 11, :o8, 1320573600
          tz.transition 2012, 3, :o9, 1331463600
          tz.transition 2012, 11, :o8, 1352023200
          tz.transition 2013, 3, :o9, 1362913200
          tz.transition 2013, 11, :o8, 1383472800
          tz.transition 2014, 3, :o9, 1394362800
          tz.transition 2014, 11, :o8, 1414922400
          tz.transition 2015, 3, :o9, 1425812400
          tz.transition 2015, 11, :o8, 1446372000
          tz.transition 2016, 3, :o9, 1457866800
          tz.transition 2016, 11, :o8, 1478426400
          tz.transition 2017, 3, :o9, 1489316400
          tz.transition 2017, 11, :o8, 1509876000
          tz.transition 2018, 3, :o9, 1520766000
          tz.transition 2018, 11, :o8, 1541325600
          tz.transition 2019, 3, :o9, 1552215600
          tz.transition 2019, 11, :o8, 1572775200
          tz.transition 2020, 3, :o9, 1583665200
          tz.transition 2020, 11, :o8, 1604224800
          tz.transition 2021, 3, :o9, 1615719600
          tz.transition 2021, 11, :o8, 1636279200
          tz.transition 2022, 3, :o9, 1647169200
          tz.transition 2022, 11, :o8, 1667728800
          tz.transition 2023, 3, :o9, 1678618800
          tz.transition 2023, 11, :o8, 1699178400
          tz.transition 2024, 3, :o9, 1710068400
          tz.transition 2024, 11, :o8, 1730628000
          tz.transition 2025, 3, :o9, 1741518000
          tz.transition 2025, 11, :o8, 1762077600
          tz.transition 2026, 3, :o9, 1772967600
          tz.transition 2026, 11, :o8, 1793527200
          tz.transition 2027, 3, :o9, 1805022000
          tz.transition 2027, 11, :o8, 1825581600
          tz.transition 2028, 3, :o9, 1836471600
          tz.transition 2028, 11, :o8, 1857031200
          tz.transition 2029, 3, :o9, 1867921200
          tz.transition 2029, 11, :o8, 1888480800
          tz.transition 2030, 3, :o9, 1899370800
          tz.transition 2030, 11, :o8, 1919930400
          tz.transition 2031, 3, :o9, 1930820400
          tz.transition 2031, 11, :o8, 1951380000
          tz.transition 2032, 3, :o9, 1962874800
          tz.transition 2032, 11, :o8, 1983434400
          tz.transition 2033, 3, :o9, 1994324400
          tz.transition 2033, 11, :o8, 2014884000
          tz.transition 2034, 3, :o9, 2025774000
          tz.transition 2034, 11, :o8, 2046333600
          tz.transition 2035, 3, :o9, 2057223600
          tz.transition 2035, 11, :o8, 2077783200
          tz.transition 2036, 3, :o9, 2088673200
          tz.transition 2036, 11, :o8, 2109232800
          tz.transition 2037, 3, :o9, 2120122800
          tz.transition 2037, 11, :o8, 2140682400
          tz.transition 2038, 3, :o9, 59171927, 24
          tz.transition 2038, 11, :o8, 29588819, 12
          tz.transition 2039, 3, :o9, 59180663, 24
          tz.transition 2039, 11, :o8, 29593187, 12
          tz.transition 2040, 3, :o9, 59189399, 24
          tz.transition 2040, 11, :o8, 29597555, 12
          tz.transition 2041, 3, :o9, 59198135, 24
          tz.transition 2041, 11, :o8, 29601923, 12
          tz.transition 2042, 3, :o9, 59206871, 24
          tz.transition 2042, 11, :o8, 29606291, 12
          tz.transition 2043, 3, :o9, 59215607, 24
          tz.transition 2043, 11, :o8, 29610659, 12
          tz.transition 2044, 3, :o9, 59224511, 24
          tz.transition 2044, 11, :o8, 29615111, 12
          tz.transition 2045, 3, :o9, 59233247, 24
          tz.transition 2045, 11, :o8, 29619479, 12
          tz.transition 2046, 3, :o9, 59241983, 24
          tz.transition 2046, 11, :o8, 29623847, 12
          tz.transition 2047, 3, :o9, 59250719, 24
          tz.transition 2047, 11, :o8, 29628215, 12
          tz.transition 2048, 3, :o9, 59259455, 24
          tz.transition 2048, 11, :o8, 29632583, 12
          tz.transition 2049, 3, :o9, 59268359, 24
          tz.transition 2049, 11, :o8, 29637035, 12
          tz.transition 2050, 3, :o9, 59277095, 24
          tz.transition 2050, 11, :o8, 29641403, 12
        end
      end
    end
  end
end
