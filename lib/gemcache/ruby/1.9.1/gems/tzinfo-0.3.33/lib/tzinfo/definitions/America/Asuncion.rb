module TZInfo
  module Definitions
    module America
      module Asuncion
        include TimezoneDefinition
        
        timezone 'America/Asuncion' do |tz|
          tz.offset :o0, -13840, 0, :LMT
          tz.offset :o1, -13840, 0, :AMT
          tz.offset :o2, -14400, 0, :PYT
          tz.offset :o3, -10800, 0, :PYT
          tz.offset :o4, -14400, 3600, :PYST
          
          tz.transition 1890, 1, :o1, 2604278153, 1080
          tz.transition 1931, 10, :o2, 2620754633, 1080
          tz.transition 1972, 10, :o3, 86760000
          tz.transition 1974, 4, :o2, 134017200
          tz.transition 1975, 10, :o4, 181368000
          tz.transition 1976, 3, :o2, 194497200
          tz.transition 1976, 10, :o4, 212990400
          tz.transition 1977, 3, :o2, 226033200
          tz.transition 1977, 10, :o4, 244526400
          tz.transition 1978, 3, :o2, 257569200
          tz.transition 1978, 10, :o4, 276062400
          tz.transition 1979, 4, :o2, 291783600
          tz.transition 1979, 10, :o4, 307598400
          tz.transition 1980, 4, :o2, 323406000
          tz.transition 1980, 10, :o4, 339220800
          tz.transition 1981, 4, :o2, 354942000
          tz.transition 1981, 10, :o4, 370756800
          tz.transition 1982, 4, :o2, 386478000
          tz.transition 1982, 10, :o4, 402292800
          tz.transition 1983, 4, :o2, 418014000
          tz.transition 1983, 10, :o4, 433828800
          tz.transition 1984, 4, :o2, 449636400
          tz.transition 1984, 10, :o4, 465451200
          tz.transition 1985, 4, :o2, 481172400
          tz.transition 1985, 10, :o4, 496987200
          tz.transition 1986, 4, :o2, 512708400
          tz.transition 1986, 10, :o4, 528523200
          tz.transition 1987, 4, :o2, 544244400
          tz.transition 1987, 10, :o4, 560059200
          tz.transition 1988, 4, :o2, 575866800
          tz.transition 1988, 10, :o4, 591681600
          tz.transition 1989, 4, :o2, 607402800
          tz.transition 1989, 10, :o4, 625032000
          tz.transition 1990, 4, :o2, 638938800
          tz.transition 1990, 10, :o4, 654753600
          tz.transition 1991, 4, :o2, 670474800
          tz.transition 1991, 10, :o4, 686721600
          tz.transition 1992, 3, :o2, 699418800
          tz.transition 1992, 10, :o4, 718257600
          tz.transition 1993, 3, :o2, 733546800
          tz.transition 1993, 10, :o4, 749448000
          tz.transition 1994, 2, :o2, 762318000
          tz.transition 1994, 10, :o4, 780984000
          tz.transition 1995, 2, :o2, 793767600
          tz.transition 1995, 10, :o4, 812520000
          tz.transition 1996, 3, :o2, 825649200
          tz.transition 1996, 10, :o4, 844574400
          tz.transition 1997, 2, :o2, 856666800
          tz.transition 1997, 10, :o4, 876024000
          tz.transition 1998, 3, :o2, 888721200
          tz.transition 1998, 10, :o4, 907473600
          tz.transition 1999, 3, :o2, 920775600
          tz.transition 1999, 10, :o4, 938923200
          tz.transition 2000, 3, :o2, 952225200
          tz.transition 2000, 10, :o4, 970372800
          tz.transition 2001, 3, :o2, 983674800
          tz.transition 2001, 10, :o4, 1002427200
          tz.transition 2002, 4, :o2, 1018148400
          tz.transition 2002, 9, :o4, 1030852800
          tz.transition 2003, 4, :o2, 1049598000
          tz.transition 2003, 9, :o4, 1062907200
          tz.transition 2004, 4, :o2, 1081047600
          tz.transition 2004, 10, :o4, 1097985600
          tz.transition 2005, 3, :o2, 1110682800
          tz.transition 2005, 10, :o4, 1129435200
          tz.transition 2006, 3, :o2, 1142132400
          tz.transition 2006, 10, :o4, 1160884800
          tz.transition 2007, 3, :o2, 1173582000
          tz.transition 2007, 10, :o4, 1192939200
          tz.transition 2008, 3, :o2, 1205031600
          tz.transition 2008, 10, :o4, 1224388800
          tz.transition 2009, 3, :o2, 1236481200
          tz.transition 2009, 10, :o4, 1255838400
          tz.transition 2010, 4, :o2, 1270954800
          tz.transition 2010, 10, :o4, 1286078400
          tz.transition 2011, 4, :o2, 1302404400
          tz.transition 2011, 10, :o4, 1317528000
          tz.transition 2012, 4, :o2, 1333854000
          tz.transition 2012, 10, :o4, 1349582400
          tz.transition 2013, 4, :o2, 1365908400
          tz.transition 2013, 10, :o4, 1381032000
          tz.transition 2014, 4, :o2, 1397358000
          tz.transition 2014, 10, :o4, 1412481600
          tz.transition 2015, 4, :o2, 1428807600
          tz.transition 2015, 10, :o4, 1443931200
          tz.transition 2016, 4, :o2, 1460257200
          tz.transition 2016, 10, :o4, 1475380800
          tz.transition 2017, 4, :o2, 1491706800
          tz.transition 2017, 10, :o4, 1506830400
          tz.transition 2018, 4, :o2, 1523156400
          tz.transition 2018, 10, :o4, 1538884800
          tz.transition 2019, 4, :o2, 1555210800
          tz.transition 2019, 10, :o4, 1570334400
          tz.transition 2020, 4, :o2, 1586660400
          tz.transition 2020, 10, :o4, 1601784000
          tz.transition 2021, 4, :o2, 1618110000
          tz.transition 2021, 10, :o4, 1633233600
          tz.transition 2022, 4, :o2, 1649559600
          tz.transition 2022, 10, :o4, 1664683200
          tz.transition 2023, 4, :o2, 1681009200
          tz.transition 2023, 10, :o4, 1696132800
          tz.transition 2024, 4, :o2, 1713063600
          tz.transition 2024, 10, :o4, 1728187200
          tz.transition 2025, 4, :o2, 1744513200
          tz.transition 2025, 10, :o4, 1759636800
          tz.transition 2026, 4, :o2, 1775962800
          tz.transition 2026, 10, :o4, 1791086400
          tz.transition 2027, 4, :o2, 1807412400
          tz.transition 2027, 10, :o4, 1822536000
          tz.transition 2028, 4, :o2, 1838862000
          tz.transition 2028, 10, :o4, 1853985600
          tz.transition 2029, 4, :o2, 1870311600
          tz.transition 2029, 10, :o4, 1886040000
          tz.transition 2030, 4, :o2, 1902366000
          tz.transition 2030, 10, :o4, 1917489600
          tz.transition 2031, 4, :o2, 1933815600
          tz.transition 2031, 10, :o4, 1948939200
          tz.transition 2032, 4, :o2, 1965265200
          tz.transition 2032, 10, :o4, 1980388800
          tz.transition 2033, 4, :o2, 1996714800
          tz.transition 2033, 10, :o4, 2011838400
          tz.transition 2034, 4, :o2, 2028164400
          tz.transition 2034, 10, :o4, 2043288000
          tz.transition 2035, 4, :o2, 2059614000
          tz.transition 2035, 10, :o4, 2075342400
          tz.transition 2036, 4, :o2, 2091668400
          tz.transition 2036, 10, :o4, 2106792000
          tz.transition 2037, 4, :o2, 2123118000
          tz.transition 2037, 10, :o4, 2138241600
          tz.transition 2038, 4, :o2, 19724197, 8
          tz.transition 2038, 10, :o4, 7397099, 3
          tz.transition 2039, 4, :o2, 19727109, 8
          tz.transition 2039, 10, :o4, 7398191, 3
          tz.transition 2040, 4, :o2, 19730021, 8
          tz.transition 2040, 10, :o4, 7399304, 3
          tz.transition 2041, 4, :o2, 19732989, 8
          tz.transition 2041, 10, :o4, 7400396, 3
          tz.transition 2042, 4, :o2, 19735901, 8
          tz.transition 2042, 10, :o4, 7401488, 3
          tz.transition 2043, 4, :o2, 19738813, 8
          tz.transition 2043, 10, :o4, 7402580, 3
          tz.transition 2044, 4, :o2, 19741725, 8
          tz.transition 2044, 10, :o4, 7403672, 3
          tz.transition 2045, 4, :o2, 19744637, 8
          tz.transition 2045, 10, :o4, 7404764, 3
          tz.transition 2046, 4, :o2, 19747549, 8
          tz.transition 2046, 10, :o4, 7405877, 3
          tz.transition 2047, 4, :o2, 19750517, 8
          tz.transition 2047, 10, :o4, 7406969, 3
          tz.transition 2048, 4, :o2, 19753429, 8
          tz.transition 2048, 10, :o4, 7408061, 3
          tz.transition 2049, 4, :o2, 19756341, 8
          tz.transition 2049, 10, :o4, 7409153, 3
          tz.transition 2050, 4, :o2, 19759253, 8
        end
      end
    end
  end
end
