module TZInfo
  module Definitions
    module America
      module Cambridge_Bay
        include TimezoneDefinition
        
        timezone 'America/Cambridge_Bay' do |tz|
          tz.offset :o0, 0, 0, :zzz
          tz.offset :o1, -25200, 0, :MST
          tz.offset :o2, -25200, 3600, :MWT
          tz.offset :o3, -25200, 3600, :MPT
          tz.offset :o4, -25200, 7200, :MDDT
          tz.offset :o5, -25200, 3600, :MDT
          tz.offset :o6, -21600, 0, :CST
          tz.offset :o7, -21600, 3600, :CDT
          tz.offset :o8, -18000, 0, :EST
          
          tz.transition 1920, 1, :o1, 4844649, 2
          tz.transition 1942, 2, :o2, 19443199, 8
          tz.transition 1945, 8, :o3, 58360379, 24
          tz.transition 1945, 9, :o1, 14590373, 6
          tz.transition 1965, 4, :o4, 58533019, 24
          tz.transition 1965, 10, :o1, 58537555, 24
          tz.transition 1980, 4, :o5, 325674000
          tz.transition 1980, 10, :o1, 341395200
          tz.transition 1981, 4, :o5, 357123600
          tz.transition 1981, 10, :o1, 372844800
          tz.transition 1982, 4, :o5, 388573200
          tz.transition 1982, 10, :o1, 404899200
          tz.transition 1983, 4, :o5, 420022800
          tz.transition 1983, 10, :o1, 436348800
          tz.transition 1984, 4, :o5, 452077200
          tz.transition 1984, 10, :o1, 467798400
          tz.transition 1985, 4, :o5, 483526800
          tz.transition 1985, 10, :o1, 499248000
          tz.transition 1986, 4, :o5, 514976400
          tz.transition 1986, 10, :o1, 530697600
          tz.transition 1987, 4, :o5, 544611600
          tz.transition 1987, 10, :o1, 562147200
          tz.transition 1988, 4, :o5, 576061200
          tz.transition 1988, 10, :o1, 594201600
          tz.transition 1989, 4, :o5, 607510800
          tz.transition 1989, 10, :o1, 625651200
          tz.transition 1990, 4, :o5, 638960400
          tz.transition 1990, 10, :o1, 657100800
          tz.transition 1991, 4, :o5, 671014800
          tz.transition 1991, 10, :o1, 688550400
          tz.transition 1992, 4, :o5, 702464400
          tz.transition 1992, 10, :o1, 720000000
          tz.transition 1993, 4, :o5, 733914000
          tz.transition 1993, 10, :o1, 752054400
          tz.transition 1994, 4, :o5, 765363600
          tz.transition 1994, 10, :o1, 783504000
          tz.transition 1995, 4, :o5, 796813200
          tz.transition 1995, 10, :o1, 814953600
          tz.transition 1996, 4, :o5, 828867600
          tz.transition 1996, 10, :o1, 846403200
          tz.transition 1997, 4, :o5, 860317200
          tz.transition 1997, 10, :o1, 877852800
          tz.transition 1998, 4, :o5, 891766800
          tz.transition 1998, 10, :o1, 909302400
          tz.transition 1999, 4, :o5, 923216400
          tz.transition 1999, 10, :o6, 941356800
          tz.transition 2000, 4, :o7, 954662400
          tz.transition 2000, 10, :o8, 972802800
          tz.transition 2000, 11, :o6, 973400400
          tz.transition 2001, 4, :o5, 986115600
          tz.transition 2001, 10, :o1, 1004256000
          tz.transition 2002, 4, :o5, 1018170000
          tz.transition 2002, 10, :o1, 1035705600
          tz.transition 2003, 4, :o5, 1049619600
          tz.transition 2003, 10, :o1, 1067155200
          tz.transition 2004, 4, :o5, 1081069200
          tz.transition 2004, 10, :o1, 1099209600
          tz.transition 2005, 4, :o5, 1112518800
          tz.transition 2005, 10, :o1, 1130659200
          tz.transition 2006, 4, :o5, 1143968400
          tz.transition 2006, 10, :o1, 1162108800
          tz.transition 2007, 3, :o5, 1173603600
          tz.transition 2007, 11, :o1, 1194163200
          tz.transition 2008, 3, :o5, 1205053200
          tz.transition 2008, 11, :o1, 1225612800
          tz.transition 2009, 3, :o5, 1236502800
          tz.transition 2009, 11, :o1, 1257062400
          tz.transition 2010, 3, :o5, 1268557200
          tz.transition 2010, 11, :o1, 1289116800
          tz.transition 2011, 3, :o5, 1300006800
          tz.transition 2011, 11, :o1, 1320566400
          tz.transition 2012, 3, :o5, 1331456400
          tz.transition 2012, 11, :o1, 1352016000
          tz.transition 2013, 3, :o5, 1362906000
          tz.transition 2013, 11, :o1, 1383465600
          tz.transition 2014, 3, :o5, 1394355600
          tz.transition 2014, 11, :o1, 1414915200
          tz.transition 2015, 3, :o5, 1425805200
          tz.transition 2015, 11, :o1, 1446364800
          tz.transition 2016, 3, :o5, 1457859600
          tz.transition 2016, 11, :o1, 1478419200
          tz.transition 2017, 3, :o5, 1489309200
          tz.transition 2017, 11, :o1, 1509868800
          tz.transition 2018, 3, :o5, 1520758800
          tz.transition 2018, 11, :o1, 1541318400
          tz.transition 2019, 3, :o5, 1552208400
          tz.transition 2019, 11, :o1, 1572768000
          tz.transition 2020, 3, :o5, 1583658000
          tz.transition 2020, 11, :o1, 1604217600
          tz.transition 2021, 3, :o5, 1615712400
          tz.transition 2021, 11, :o1, 1636272000
          tz.transition 2022, 3, :o5, 1647162000
          tz.transition 2022, 11, :o1, 1667721600
          tz.transition 2023, 3, :o5, 1678611600
          tz.transition 2023, 11, :o1, 1699171200
          tz.transition 2024, 3, :o5, 1710061200
          tz.transition 2024, 11, :o1, 1730620800
          tz.transition 2025, 3, :o5, 1741510800
          tz.transition 2025, 11, :o1, 1762070400
          tz.transition 2026, 3, :o5, 1772960400
          tz.transition 2026, 11, :o1, 1793520000
          tz.transition 2027, 3, :o5, 1805014800
          tz.transition 2027, 11, :o1, 1825574400
          tz.transition 2028, 3, :o5, 1836464400
          tz.transition 2028, 11, :o1, 1857024000
          tz.transition 2029, 3, :o5, 1867914000
          tz.transition 2029, 11, :o1, 1888473600
          tz.transition 2030, 3, :o5, 1899363600
          tz.transition 2030, 11, :o1, 1919923200
          tz.transition 2031, 3, :o5, 1930813200
          tz.transition 2031, 11, :o1, 1951372800
          tz.transition 2032, 3, :o5, 1962867600
          tz.transition 2032, 11, :o1, 1983427200
          tz.transition 2033, 3, :o5, 1994317200
          tz.transition 2033, 11, :o1, 2014876800
          tz.transition 2034, 3, :o5, 2025766800
          tz.transition 2034, 11, :o1, 2046326400
          tz.transition 2035, 3, :o5, 2057216400
          tz.transition 2035, 11, :o1, 2077776000
          tz.transition 2036, 3, :o5, 2088666000
          tz.transition 2036, 11, :o1, 2109225600
          tz.transition 2037, 3, :o5, 2120115600
          tz.transition 2037, 11, :o1, 2140675200
          tz.transition 2038, 3, :o5, 19723975, 8
          tz.transition 2038, 11, :o1, 14794409, 6
          tz.transition 2039, 3, :o5, 19726887, 8
          tz.transition 2039, 11, :o1, 14796593, 6
          tz.transition 2040, 3, :o5, 19729799, 8
          tz.transition 2040, 11, :o1, 14798777, 6
          tz.transition 2041, 3, :o5, 19732711, 8
          tz.transition 2041, 11, :o1, 14800961, 6
          tz.transition 2042, 3, :o5, 19735623, 8
          tz.transition 2042, 11, :o1, 14803145, 6
          tz.transition 2043, 3, :o5, 19738535, 8
          tz.transition 2043, 11, :o1, 14805329, 6
          tz.transition 2044, 3, :o5, 19741503, 8
          tz.transition 2044, 11, :o1, 14807555, 6
          tz.transition 2045, 3, :o5, 19744415, 8
          tz.transition 2045, 11, :o1, 14809739, 6
          tz.transition 2046, 3, :o5, 19747327, 8
          tz.transition 2046, 11, :o1, 14811923, 6
          tz.transition 2047, 3, :o5, 19750239, 8
          tz.transition 2047, 11, :o1, 14814107, 6
          tz.transition 2048, 3, :o5, 19753151, 8
          tz.transition 2048, 11, :o1, 14816291, 6
          tz.transition 2049, 3, :o5, 19756119, 8
          tz.transition 2049, 11, :o1, 14818517, 6
          tz.transition 2050, 3, :o5, 19759031, 8
          tz.transition 2050, 11, :o1, 14820701, 6
        end
      end
    end
  end
end
