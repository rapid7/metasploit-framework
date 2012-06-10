module TZInfo
  module Definitions
    module America
      module Yakutat
        include TimezoneDefinition
        
        timezone 'America/Yakutat' do |tz|
          tz.offset :o0, 52865, 0, :LMT
          tz.offset :o1, -33535, 0, :LMT
          tz.offset :o2, -32400, 0, :YST
          tz.offset :o3, -32400, 3600, :YWT
          tz.offset :o4, -32400, 3600, :YPT
          tz.offset :o5, -32400, 3600, :YDT
          tz.offset :o6, -32400, 0, :AKST
          tz.offset :o7, -32400, 3600, :AKDT
          
          tz.transition 1867, 10, :o1, 41528279027, 17280
          tz.transition 1900, 8, :o2, 41735561267, 17280
          tz.transition 1942, 2, :o3, 58329599, 24
          tz.transition 1945, 8, :o4, 58360379, 24
          tz.transition 1945, 9, :o2, 29180747, 12
          tz.transition 1969, 4, :o5, 58568135, 24
          tz.transition 1969, 10, :o2, 29286251, 12
          tz.transition 1970, 4, :o5, 9975600
          tz.transition 1970, 10, :o2, 25696800
          tz.transition 1971, 4, :o5, 41425200
          tz.transition 1971, 10, :o2, 57751200
          tz.transition 1972, 4, :o5, 73479600
          tz.transition 1972, 10, :o2, 89200800
          tz.transition 1973, 4, :o5, 104929200
          tz.transition 1973, 10, :o2, 120650400
          tz.transition 1974, 1, :o5, 126702000
          tz.transition 1974, 10, :o2, 152100000
          tz.transition 1975, 2, :o5, 162385200
          tz.transition 1975, 10, :o2, 183549600
          tz.transition 1976, 4, :o5, 199278000
          tz.transition 1976, 10, :o2, 215604000
          tz.transition 1977, 4, :o5, 230727600
          tz.transition 1977, 10, :o2, 247053600
          tz.transition 1978, 4, :o5, 262782000
          tz.transition 1978, 10, :o2, 278503200
          tz.transition 1979, 4, :o5, 294231600
          tz.transition 1979, 10, :o2, 309952800
          tz.transition 1980, 4, :o5, 325681200
          tz.transition 1980, 10, :o2, 341402400
          tz.transition 1981, 4, :o5, 357130800
          tz.transition 1981, 10, :o2, 372852000
          tz.transition 1982, 4, :o5, 388580400
          tz.transition 1982, 10, :o2, 404906400
          tz.transition 1983, 4, :o5, 420030000
          tz.transition 1983, 10, :o2, 436356000
          tz.transition 1983, 11, :o6, 439030800
          tz.transition 1984, 4, :o7, 452084400
          tz.transition 1984, 10, :o6, 467805600
          tz.transition 1985, 4, :o7, 483534000
          tz.transition 1985, 10, :o6, 499255200
          tz.transition 1986, 4, :o7, 514983600
          tz.transition 1986, 10, :o6, 530704800
          tz.transition 1987, 4, :o7, 544618800
          tz.transition 1987, 10, :o6, 562154400
          tz.transition 1988, 4, :o7, 576068400
          tz.transition 1988, 10, :o6, 594208800
          tz.transition 1989, 4, :o7, 607518000
          tz.transition 1989, 10, :o6, 625658400
          tz.transition 1990, 4, :o7, 638967600
          tz.transition 1990, 10, :o6, 657108000
          tz.transition 1991, 4, :o7, 671022000
          tz.transition 1991, 10, :o6, 688557600
          tz.transition 1992, 4, :o7, 702471600
          tz.transition 1992, 10, :o6, 720007200
          tz.transition 1993, 4, :o7, 733921200
          tz.transition 1993, 10, :o6, 752061600
          tz.transition 1994, 4, :o7, 765370800
          tz.transition 1994, 10, :o6, 783511200
          tz.transition 1995, 4, :o7, 796820400
          tz.transition 1995, 10, :o6, 814960800
          tz.transition 1996, 4, :o7, 828874800
          tz.transition 1996, 10, :o6, 846410400
          tz.transition 1997, 4, :o7, 860324400
          tz.transition 1997, 10, :o6, 877860000
          tz.transition 1998, 4, :o7, 891774000
          tz.transition 1998, 10, :o6, 909309600
          tz.transition 1999, 4, :o7, 923223600
          tz.transition 1999, 10, :o6, 941364000
          tz.transition 2000, 4, :o7, 954673200
          tz.transition 2000, 10, :o6, 972813600
          tz.transition 2001, 4, :o7, 986122800
          tz.transition 2001, 10, :o6, 1004263200
          tz.transition 2002, 4, :o7, 1018177200
          tz.transition 2002, 10, :o6, 1035712800
          tz.transition 2003, 4, :o7, 1049626800
          tz.transition 2003, 10, :o6, 1067162400
          tz.transition 2004, 4, :o7, 1081076400
          tz.transition 2004, 10, :o6, 1099216800
          tz.transition 2005, 4, :o7, 1112526000
          tz.transition 2005, 10, :o6, 1130666400
          tz.transition 2006, 4, :o7, 1143975600
          tz.transition 2006, 10, :o6, 1162116000
          tz.transition 2007, 3, :o7, 1173610800
          tz.transition 2007, 11, :o6, 1194170400
          tz.transition 2008, 3, :o7, 1205060400
          tz.transition 2008, 11, :o6, 1225620000
          tz.transition 2009, 3, :o7, 1236510000
          tz.transition 2009, 11, :o6, 1257069600
          tz.transition 2010, 3, :o7, 1268564400
          tz.transition 2010, 11, :o6, 1289124000
          tz.transition 2011, 3, :o7, 1300014000
          tz.transition 2011, 11, :o6, 1320573600
          tz.transition 2012, 3, :o7, 1331463600
          tz.transition 2012, 11, :o6, 1352023200
          tz.transition 2013, 3, :o7, 1362913200
          tz.transition 2013, 11, :o6, 1383472800
          tz.transition 2014, 3, :o7, 1394362800
          tz.transition 2014, 11, :o6, 1414922400
          tz.transition 2015, 3, :o7, 1425812400
          tz.transition 2015, 11, :o6, 1446372000
          tz.transition 2016, 3, :o7, 1457866800
          tz.transition 2016, 11, :o6, 1478426400
          tz.transition 2017, 3, :o7, 1489316400
          tz.transition 2017, 11, :o6, 1509876000
          tz.transition 2018, 3, :o7, 1520766000
          tz.transition 2018, 11, :o6, 1541325600
          tz.transition 2019, 3, :o7, 1552215600
          tz.transition 2019, 11, :o6, 1572775200
          tz.transition 2020, 3, :o7, 1583665200
          tz.transition 2020, 11, :o6, 1604224800
          tz.transition 2021, 3, :o7, 1615719600
          tz.transition 2021, 11, :o6, 1636279200
          tz.transition 2022, 3, :o7, 1647169200
          tz.transition 2022, 11, :o6, 1667728800
          tz.transition 2023, 3, :o7, 1678618800
          tz.transition 2023, 11, :o6, 1699178400
          tz.transition 2024, 3, :o7, 1710068400
          tz.transition 2024, 11, :o6, 1730628000
          tz.transition 2025, 3, :o7, 1741518000
          tz.transition 2025, 11, :o6, 1762077600
          tz.transition 2026, 3, :o7, 1772967600
          tz.transition 2026, 11, :o6, 1793527200
          tz.transition 2027, 3, :o7, 1805022000
          tz.transition 2027, 11, :o6, 1825581600
          tz.transition 2028, 3, :o7, 1836471600
          tz.transition 2028, 11, :o6, 1857031200
          tz.transition 2029, 3, :o7, 1867921200
          tz.transition 2029, 11, :o6, 1888480800
          tz.transition 2030, 3, :o7, 1899370800
          tz.transition 2030, 11, :o6, 1919930400
          tz.transition 2031, 3, :o7, 1930820400
          tz.transition 2031, 11, :o6, 1951380000
          tz.transition 2032, 3, :o7, 1962874800
          tz.transition 2032, 11, :o6, 1983434400
          tz.transition 2033, 3, :o7, 1994324400
          tz.transition 2033, 11, :o6, 2014884000
          tz.transition 2034, 3, :o7, 2025774000
          tz.transition 2034, 11, :o6, 2046333600
          tz.transition 2035, 3, :o7, 2057223600
          tz.transition 2035, 11, :o6, 2077783200
          tz.transition 2036, 3, :o7, 2088673200
          tz.transition 2036, 11, :o6, 2109232800
          tz.transition 2037, 3, :o7, 2120122800
          tz.transition 2037, 11, :o6, 2140682400
          tz.transition 2038, 3, :o7, 59171927, 24
          tz.transition 2038, 11, :o6, 29588819, 12
          tz.transition 2039, 3, :o7, 59180663, 24
          tz.transition 2039, 11, :o6, 29593187, 12
          tz.transition 2040, 3, :o7, 59189399, 24
          tz.transition 2040, 11, :o6, 29597555, 12
          tz.transition 2041, 3, :o7, 59198135, 24
          tz.transition 2041, 11, :o6, 29601923, 12
          tz.transition 2042, 3, :o7, 59206871, 24
          tz.transition 2042, 11, :o6, 29606291, 12
          tz.transition 2043, 3, :o7, 59215607, 24
          tz.transition 2043, 11, :o6, 29610659, 12
          tz.transition 2044, 3, :o7, 59224511, 24
          tz.transition 2044, 11, :o6, 29615111, 12
          tz.transition 2045, 3, :o7, 59233247, 24
          tz.transition 2045, 11, :o6, 29619479, 12
          tz.transition 2046, 3, :o7, 59241983, 24
          tz.transition 2046, 11, :o6, 29623847, 12
          tz.transition 2047, 3, :o7, 59250719, 24
          tz.transition 2047, 11, :o6, 29628215, 12
          tz.transition 2048, 3, :o7, 59259455, 24
          tz.transition 2048, 11, :o6, 29632583, 12
          tz.transition 2049, 3, :o7, 59268359, 24
          tz.transition 2049, 11, :o6, 29637035, 12
          tz.transition 2050, 3, :o7, 59277095, 24
          tz.transition 2050, 11, :o6, 29641403, 12
        end
      end
    end
  end
end
