module TZInfo
  module Definitions
    module America
      module Boise
        include TimezoneDefinition
        
        timezone 'America/Boise' do |tz|
          tz.offset :o0, -27889, 0, :LMT
          tz.offset :o1, -28800, 0, :PST
          tz.offset :o2, -28800, 3600, :PDT
          tz.offset :o3, -25200, 0, :MST
          tz.offset :o4, -25200, 3600, :MWT
          tz.offset :o5, -25200, 3600, :MPT
          tz.offset :o6, -25200, 3600, :MDT
          
          tz.transition 1883, 11, :o1, 7227400, 3
          tz.transition 1918, 3, :o2, 29060207, 12
          tz.transition 1918, 10, :o1, 19375151, 8
          tz.transition 1919, 3, :o2, 29064575, 12
          tz.transition 1919, 10, :o1, 19378063, 8
          tz.transition 1923, 5, :o3, 29082635, 12
          tz.transition 1942, 2, :o4, 19443199, 8
          tz.transition 1945, 8, :o5, 58360379, 24
          tz.transition 1945, 9, :o3, 14590373, 6
          tz.transition 1967, 4, :o6, 19516887, 8
          tz.transition 1967, 10, :o3, 14638757, 6
          tz.transition 1968, 4, :o6, 19519799, 8
          tz.transition 1968, 10, :o3, 14640941, 6
          tz.transition 1969, 4, :o6, 19522711, 8
          tz.transition 1969, 10, :o3, 14643125, 6
          tz.transition 1970, 4, :o6, 9968400
          tz.transition 1970, 10, :o3, 25689600
          tz.transition 1971, 4, :o6, 41418000
          tz.transition 1971, 10, :o3, 57744000
          tz.transition 1972, 4, :o6, 73472400
          tz.transition 1972, 10, :o3, 89193600
          tz.transition 1973, 4, :o6, 104922000
          tz.transition 1973, 10, :o3, 120643200
          tz.transition 1974, 2, :o6, 129114000
          tz.transition 1974, 10, :o3, 152092800
          tz.transition 1975, 2, :o6, 162378000
          tz.transition 1975, 10, :o3, 183542400
          tz.transition 1976, 4, :o6, 199270800
          tz.transition 1976, 10, :o3, 215596800
          tz.transition 1977, 4, :o6, 230720400
          tz.transition 1977, 10, :o3, 247046400
          tz.transition 1978, 4, :o6, 262774800
          tz.transition 1978, 10, :o3, 278496000
          tz.transition 1979, 4, :o6, 294224400
          tz.transition 1979, 10, :o3, 309945600
          tz.transition 1980, 4, :o6, 325674000
          tz.transition 1980, 10, :o3, 341395200
          tz.transition 1981, 4, :o6, 357123600
          tz.transition 1981, 10, :o3, 372844800
          tz.transition 1982, 4, :o6, 388573200
          tz.transition 1982, 10, :o3, 404899200
          tz.transition 1983, 4, :o6, 420022800
          tz.transition 1983, 10, :o3, 436348800
          tz.transition 1984, 4, :o6, 452077200
          tz.transition 1984, 10, :o3, 467798400
          tz.transition 1985, 4, :o6, 483526800
          tz.transition 1985, 10, :o3, 499248000
          tz.transition 1986, 4, :o6, 514976400
          tz.transition 1986, 10, :o3, 530697600
          tz.transition 1987, 4, :o6, 544611600
          tz.transition 1987, 10, :o3, 562147200
          tz.transition 1988, 4, :o6, 576061200
          tz.transition 1988, 10, :o3, 594201600
          tz.transition 1989, 4, :o6, 607510800
          tz.transition 1989, 10, :o3, 625651200
          tz.transition 1990, 4, :o6, 638960400
          tz.transition 1990, 10, :o3, 657100800
          tz.transition 1991, 4, :o6, 671014800
          tz.transition 1991, 10, :o3, 688550400
          tz.transition 1992, 4, :o6, 702464400
          tz.transition 1992, 10, :o3, 720000000
          tz.transition 1993, 4, :o6, 733914000
          tz.transition 1993, 10, :o3, 752054400
          tz.transition 1994, 4, :o6, 765363600
          tz.transition 1994, 10, :o3, 783504000
          tz.transition 1995, 4, :o6, 796813200
          tz.transition 1995, 10, :o3, 814953600
          tz.transition 1996, 4, :o6, 828867600
          tz.transition 1996, 10, :o3, 846403200
          tz.transition 1997, 4, :o6, 860317200
          tz.transition 1997, 10, :o3, 877852800
          tz.transition 1998, 4, :o6, 891766800
          tz.transition 1998, 10, :o3, 909302400
          tz.transition 1999, 4, :o6, 923216400
          tz.transition 1999, 10, :o3, 941356800
          tz.transition 2000, 4, :o6, 954666000
          tz.transition 2000, 10, :o3, 972806400
          tz.transition 2001, 4, :o6, 986115600
          tz.transition 2001, 10, :o3, 1004256000
          tz.transition 2002, 4, :o6, 1018170000
          tz.transition 2002, 10, :o3, 1035705600
          tz.transition 2003, 4, :o6, 1049619600
          tz.transition 2003, 10, :o3, 1067155200
          tz.transition 2004, 4, :o6, 1081069200
          tz.transition 2004, 10, :o3, 1099209600
          tz.transition 2005, 4, :o6, 1112518800
          tz.transition 2005, 10, :o3, 1130659200
          tz.transition 2006, 4, :o6, 1143968400
          tz.transition 2006, 10, :o3, 1162108800
          tz.transition 2007, 3, :o6, 1173603600
          tz.transition 2007, 11, :o3, 1194163200
          tz.transition 2008, 3, :o6, 1205053200
          tz.transition 2008, 11, :o3, 1225612800
          tz.transition 2009, 3, :o6, 1236502800
          tz.transition 2009, 11, :o3, 1257062400
          tz.transition 2010, 3, :o6, 1268557200
          tz.transition 2010, 11, :o3, 1289116800
          tz.transition 2011, 3, :o6, 1300006800
          tz.transition 2011, 11, :o3, 1320566400
          tz.transition 2012, 3, :o6, 1331456400
          tz.transition 2012, 11, :o3, 1352016000
          tz.transition 2013, 3, :o6, 1362906000
          tz.transition 2013, 11, :o3, 1383465600
          tz.transition 2014, 3, :o6, 1394355600
          tz.transition 2014, 11, :o3, 1414915200
          tz.transition 2015, 3, :o6, 1425805200
          tz.transition 2015, 11, :o3, 1446364800
          tz.transition 2016, 3, :o6, 1457859600
          tz.transition 2016, 11, :o3, 1478419200
          tz.transition 2017, 3, :o6, 1489309200
          tz.transition 2017, 11, :o3, 1509868800
          tz.transition 2018, 3, :o6, 1520758800
          tz.transition 2018, 11, :o3, 1541318400
          tz.transition 2019, 3, :o6, 1552208400
          tz.transition 2019, 11, :o3, 1572768000
          tz.transition 2020, 3, :o6, 1583658000
          tz.transition 2020, 11, :o3, 1604217600
          tz.transition 2021, 3, :o6, 1615712400
          tz.transition 2021, 11, :o3, 1636272000
          tz.transition 2022, 3, :o6, 1647162000
          tz.transition 2022, 11, :o3, 1667721600
          tz.transition 2023, 3, :o6, 1678611600
          tz.transition 2023, 11, :o3, 1699171200
          tz.transition 2024, 3, :o6, 1710061200
          tz.transition 2024, 11, :o3, 1730620800
          tz.transition 2025, 3, :o6, 1741510800
          tz.transition 2025, 11, :o3, 1762070400
          tz.transition 2026, 3, :o6, 1772960400
          tz.transition 2026, 11, :o3, 1793520000
          tz.transition 2027, 3, :o6, 1805014800
          tz.transition 2027, 11, :o3, 1825574400
          tz.transition 2028, 3, :o6, 1836464400
          tz.transition 2028, 11, :o3, 1857024000
          tz.transition 2029, 3, :o6, 1867914000
          tz.transition 2029, 11, :o3, 1888473600
          tz.transition 2030, 3, :o6, 1899363600
          tz.transition 2030, 11, :o3, 1919923200
          tz.transition 2031, 3, :o6, 1930813200
          tz.transition 2031, 11, :o3, 1951372800
          tz.transition 2032, 3, :o6, 1962867600
          tz.transition 2032, 11, :o3, 1983427200
          tz.transition 2033, 3, :o6, 1994317200
          tz.transition 2033, 11, :o3, 2014876800
          tz.transition 2034, 3, :o6, 2025766800
          tz.transition 2034, 11, :o3, 2046326400
          tz.transition 2035, 3, :o6, 2057216400
          tz.transition 2035, 11, :o3, 2077776000
          tz.transition 2036, 3, :o6, 2088666000
          tz.transition 2036, 11, :o3, 2109225600
          tz.transition 2037, 3, :o6, 2120115600
          tz.transition 2037, 11, :o3, 2140675200
          tz.transition 2038, 3, :o6, 19723975, 8
          tz.transition 2038, 11, :o3, 14794409, 6
          tz.transition 2039, 3, :o6, 19726887, 8
          tz.transition 2039, 11, :o3, 14796593, 6
          tz.transition 2040, 3, :o6, 19729799, 8
          tz.transition 2040, 11, :o3, 14798777, 6
          tz.transition 2041, 3, :o6, 19732711, 8
          tz.transition 2041, 11, :o3, 14800961, 6
          tz.transition 2042, 3, :o6, 19735623, 8
          tz.transition 2042, 11, :o3, 14803145, 6
          tz.transition 2043, 3, :o6, 19738535, 8
          tz.transition 2043, 11, :o3, 14805329, 6
          tz.transition 2044, 3, :o6, 19741503, 8
          tz.transition 2044, 11, :o3, 14807555, 6
          tz.transition 2045, 3, :o6, 19744415, 8
          tz.transition 2045, 11, :o3, 14809739, 6
          tz.transition 2046, 3, :o6, 19747327, 8
          tz.transition 2046, 11, :o3, 14811923, 6
          tz.transition 2047, 3, :o6, 19750239, 8
          tz.transition 2047, 11, :o3, 14814107, 6
          tz.transition 2048, 3, :o6, 19753151, 8
          tz.transition 2048, 11, :o3, 14816291, 6
          tz.transition 2049, 3, :o6, 19756119, 8
          tz.transition 2049, 11, :o3, 14818517, 6
          tz.transition 2050, 3, :o6, 19759031, 8
          tz.transition 2050, 11, :o3, 14820701, 6
        end
      end
    end
  end
end
