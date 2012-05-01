module TZInfo
  module Definitions
    module MST7MDT
      include TimezoneDefinition
      
      timezone 'MST7MDT' do |tz|
        tz.offset :o0, -25200, 0, :MST
        tz.offset :o1, -25200, 3600, :MDT
        tz.offset :o2, -25200, 3600, :MWT
        tz.offset :o3, -25200, 3600, :MPT
        
        tz.transition 1918, 3, :o1, 19373471, 8
        tz.transition 1918, 10, :o0, 14531363, 6
        tz.transition 1919, 3, :o1, 19376383, 8
        tz.transition 1919, 10, :o0, 14533547, 6
        tz.transition 1942, 2, :o2, 19443199, 8
        tz.transition 1945, 8, :o3, 58360379, 24
        tz.transition 1945, 9, :o0, 14590373, 6
        tz.transition 1967, 4, :o1, 19516887, 8
        tz.transition 1967, 10, :o0, 14638757, 6
        tz.transition 1968, 4, :o1, 19519799, 8
        tz.transition 1968, 10, :o0, 14640941, 6
        tz.transition 1969, 4, :o1, 19522711, 8
        tz.transition 1969, 10, :o0, 14643125, 6
        tz.transition 1970, 4, :o1, 9968400
        tz.transition 1970, 10, :o0, 25689600
        tz.transition 1971, 4, :o1, 41418000
        tz.transition 1971, 10, :o0, 57744000
        tz.transition 1972, 4, :o1, 73472400
        tz.transition 1972, 10, :o0, 89193600
        tz.transition 1973, 4, :o1, 104922000
        tz.transition 1973, 10, :o0, 120643200
        tz.transition 1974, 1, :o1, 126694800
        tz.transition 1974, 10, :o0, 152092800
        tz.transition 1975, 2, :o1, 162378000
        tz.transition 1975, 10, :o0, 183542400
        tz.transition 1976, 4, :o1, 199270800
        tz.transition 1976, 10, :o0, 215596800
        tz.transition 1977, 4, :o1, 230720400
        tz.transition 1977, 10, :o0, 247046400
        tz.transition 1978, 4, :o1, 262774800
        tz.transition 1978, 10, :o0, 278496000
        tz.transition 1979, 4, :o1, 294224400
        tz.transition 1979, 10, :o0, 309945600
        tz.transition 1980, 4, :o1, 325674000
        tz.transition 1980, 10, :o0, 341395200
        tz.transition 1981, 4, :o1, 357123600
        tz.transition 1981, 10, :o0, 372844800
        tz.transition 1982, 4, :o1, 388573200
        tz.transition 1982, 10, :o0, 404899200
        tz.transition 1983, 4, :o1, 420022800
        tz.transition 1983, 10, :o0, 436348800
        tz.transition 1984, 4, :o1, 452077200
        tz.transition 1984, 10, :o0, 467798400
        tz.transition 1985, 4, :o1, 483526800
        tz.transition 1985, 10, :o0, 499248000
        tz.transition 1986, 4, :o1, 514976400
        tz.transition 1986, 10, :o0, 530697600
        tz.transition 1987, 4, :o1, 544611600
        tz.transition 1987, 10, :o0, 562147200
        tz.transition 1988, 4, :o1, 576061200
        tz.transition 1988, 10, :o0, 594201600
        tz.transition 1989, 4, :o1, 607510800
        tz.transition 1989, 10, :o0, 625651200
        tz.transition 1990, 4, :o1, 638960400
        tz.transition 1990, 10, :o0, 657100800
        tz.transition 1991, 4, :o1, 671014800
        tz.transition 1991, 10, :o0, 688550400
        tz.transition 1992, 4, :o1, 702464400
        tz.transition 1992, 10, :o0, 720000000
        tz.transition 1993, 4, :o1, 733914000
        tz.transition 1993, 10, :o0, 752054400
        tz.transition 1994, 4, :o1, 765363600
        tz.transition 1994, 10, :o0, 783504000
        tz.transition 1995, 4, :o1, 796813200
        tz.transition 1995, 10, :o0, 814953600
        tz.transition 1996, 4, :o1, 828867600
        tz.transition 1996, 10, :o0, 846403200
        tz.transition 1997, 4, :o1, 860317200
        tz.transition 1997, 10, :o0, 877852800
        tz.transition 1998, 4, :o1, 891766800
        tz.transition 1998, 10, :o0, 909302400
        tz.transition 1999, 4, :o1, 923216400
        tz.transition 1999, 10, :o0, 941356800
        tz.transition 2000, 4, :o1, 954666000
        tz.transition 2000, 10, :o0, 972806400
        tz.transition 2001, 4, :o1, 986115600
        tz.transition 2001, 10, :o0, 1004256000
        tz.transition 2002, 4, :o1, 1018170000
        tz.transition 2002, 10, :o0, 1035705600
        tz.transition 2003, 4, :o1, 1049619600
        tz.transition 2003, 10, :o0, 1067155200
        tz.transition 2004, 4, :o1, 1081069200
        tz.transition 2004, 10, :o0, 1099209600
        tz.transition 2005, 4, :o1, 1112518800
        tz.transition 2005, 10, :o0, 1130659200
        tz.transition 2006, 4, :o1, 1143968400
        tz.transition 2006, 10, :o0, 1162108800
        tz.transition 2007, 3, :o1, 1173603600
        tz.transition 2007, 11, :o0, 1194163200
        tz.transition 2008, 3, :o1, 1205053200
        tz.transition 2008, 11, :o0, 1225612800
        tz.transition 2009, 3, :o1, 1236502800
        tz.transition 2009, 11, :o0, 1257062400
        tz.transition 2010, 3, :o1, 1268557200
        tz.transition 2010, 11, :o0, 1289116800
        tz.transition 2011, 3, :o1, 1300006800
        tz.transition 2011, 11, :o0, 1320566400
        tz.transition 2012, 3, :o1, 1331456400
        tz.transition 2012, 11, :o0, 1352016000
        tz.transition 2013, 3, :o1, 1362906000
        tz.transition 2013, 11, :o0, 1383465600
        tz.transition 2014, 3, :o1, 1394355600
        tz.transition 2014, 11, :o0, 1414915200
        tz.transition 2015, 3, :o1, 1425805200
        tz.transition 2015, 11, :o0, 1446364800
        tz.transition 2016, 3, :o1, 1457859600
        tz.transition 2016, 11, :o0, 1478419200
        tz.transition 2017, 3, :o1, 1489309200
        tz.transition 2017, 11, :o0, 1509868800
        tz.transition 2018, 3, :o1, 1520758800
        tz.transition 2018, 11, :o0, 1541318400
        tz.transition 2019, 3, :o1, 1552208400
        tz.transition 2019, 11, :o0, 1572768000
        tz.transition 2020, 3, :o1, 1583658000
        tz.transition 2020, 11, :o0, 1604217600
        tz.transition 2021, 3, :o1, 1615712400
        tz.transition 2021, 11, :o0, 1636272000
        tz.transition 2022, 3, :o1, 1647162000
        tz.transition 2022, 11, :o0, 1667721600
        tz.transition 2023, 3, :o1, 1678611600
        tz.transition 2023, 11, :o0, 1699171200
        tz.transition 2024, 3, :o1, 1710061200
        tz.transition 2024, 11, :o0, 1730620800
        tz.transition 2025, 3, :o1, 1741510800
        tz.transition 2025, 11, :o0, 1762070400
        tz.transition 2026, 3, :o1, 1772960400
        tz.transition 2026, 11, :o0, 1793520000
        tz.transition 2027, 3, :o1, 1805014800
        tz.transition 2027, 11, :o0, 1825574400
        tz.transition 2028, 3, :o1, 1836464400
        tz.transition 2028, 11, :o0, 1857024000
        tz.transition 2029, 3, :o1, 1867914000
        tz.transition 2029, 11, :o0, 1888473600
        tz.transition 2030, 3, :o1, 1899363600
        tz.transition 2030, 11, :o0, 1919923200
        tz.transition 2031, 3, :o1, 1930813200
        tz.transition 2031, 11, :o0, 1951372800
        tz.transition 2032, 3, :o1, 1962867600
        tz.transition 2032, 11, :o0, 1983427200
        tz.transition 2033, 3, :o1, 1994317200
        tz.transition 2033, 11, :o0, 2014876800
        tz.transition 2034, 3, :o1, 2025766800
        tz.transition 2034, 11, :o0, 2046326400
        tz.transition 2035, 3, :o1, 2057216400
        tz.transition 2035, 11, :o0, 2077776000
        tz.transition 2036, 3, :o1, 2088666000
        tz.transition 2036, 11, :o0, 2109225600
        tz.transition 2037, 3, :o1, 2120115600
        tz.transition 2037, 11, :o0, 2140675200
        tz.transition 2038, 3, :o1, 19723975, 8
        tz.transition 2038, 11, :o0, 14794409, 6
        tz.transition 2039, 3, :o1, 19726887, 8
        tz.transition 2039, 11, :o0, 14796593, 6
        tz.transition 2040, 3, :o1, 19729799, 8
        tz.transition 2040, 11, :o0, 14798777, 6
        tz.transition 2041, 3, :o1, 19732711, 8
        tz.transition 2041, 11, :o0, 14800961, 6
        tz.transition 2042, 3, :o1, 19735623, 8
        tz.transition 2042, 11, :o0, 14803145, 6
        tz.transition 2043, 3, :o1, 19738535, 8
        tz.transition 2043, 11, :o0, 14805329, 6
        tz.transition 2044, 3, :o1, 19741503, 8
        tz.transition 2044, 11, :o0, 14807555, 6
        tz.transition 2045, 3, :o1, 19744415, 8
        tz.transition 2045, 11, :o0, 14809739, 6
        tz.transition 2046, 3, :o1, 19747327, 8
        tz.transition 2046, 11, :o0, 14811923, 6
        tz.transition 2047, 3, :o1, 19750239, 8
        tz.transition 2047, 11, :o0, 14814107, 6
        tz.transition 2048, 3, :o1, 19753151, 8
        tz.transition 2048, 11, :o0, 14816291, 6
        tz.transition 2049, 3, :o1, 19756119, 8
        tz.transition 2049, 11, :o0, 14818517, 6
        tz.transition 2050, 3, :o1, 19759031, 8
        tz.transition 2050, 11, :o0, 14820701, 6
      end
    end
  end
end
