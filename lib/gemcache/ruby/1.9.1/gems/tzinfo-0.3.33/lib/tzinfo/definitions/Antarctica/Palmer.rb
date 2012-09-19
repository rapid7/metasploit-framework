module TZInfo
  module Definitions
    module Antarctica
      module Palmer
        include TimezoneDefinition
        
        timezone 'Antarctica/Palmer' do |tz|
          tz.offset :o0, 0, 0, :zzz
          tz.offset :o1, -14400, 3600, :ARST
          tz.offset :o2, -14400, 0, :ART
          tz.offset :o3, -10800, 0, :ART
          tz.offset :o4, -10800, 3600, :ARST
          tz.offset :o5, -14400, 0, :CLT
          tz.offset :o6, -14400, 3600, :CLST
          
          tz.transition 1965, 1, :o1, 4877523, 2
          tz.transition 1965, 3, :o2, 19510565, 8
          tz.transition 1965, 10, :o1, 7317146, 3
          tz.transition 1966, 3, :o2, 19513485, 8
          tz.transition 1966, 10, :o1, 7318241, 3
          tz.transition 1967, 4, :o2, 19516661, 8
          tz.transition 1967, 10, :o1, 7319294, 3
          tz.transition 1968, 4, :o2, 19519629, 8
          tz.transition 1968, 10, :o1, 7320407, 3
          tz.transition 1969, 4, :o2, 19522541, 8
          tz.transition 1969, 10, :o3, 7321499, 3
          tz.transition 1974, 1, :o4, 128142000
          tz.transition 1974, 5, :o3, 136605600
          tz.transition 1982, 5, :o5, 389070000
          tz.transition 1982, 10, :o6, 403070400
          tz.transition 1983, 3, :o5, 416372400
          tz.transition 1983, 10, :o6, 434520000
          tz.transition 1984, 3, :o5, 447822000
          tz.transition 1984, 10, :o6, 466574400
          tz.transition 1985, 3, :o5, 479271600
          tz.transition 1985, 10, :o6, 498024000
          tz.transition 1986, 3, :o5, 510721200
          tz.transition 1986, 10, :o6, 529473600
          tz.transition 1987, 4, :o5, 545194800
          tz.transition 1987, 10, :o6, 560923200
          tz.transition 1988, 3, :o5, 574225200
          tz.transition 1988, 10, :o6, 591768000
          tz.transition 1989, 3, :o5, 605674800
          tz.transition 1989, 10, :o6, 624427200
          tz.transition 1990, 3, :o5, 637729200
          tz.transition 1990, 9, :o6, 653457600
          tz.transition 1991, 3, :o5, 668574000
          tz.transition 1991, 10, :o6, 687326400
          tz.transition 1992, 3, :o5, 700628400
          tz.transition 1992, 10, :o6, 718776000
          tz.transition 1993, 3, :o5, 732078000
          tz.transition 1993, 10, :o6, 750225600
          tz.transition 1994, 3, :o5, 763527600
          tz.transition 1994, 10, :o6, 781675200
          tz.transition 1995, 3, :o5, 794977200
          tz.transition 1995, 10, :o6, 813729600
          tz.transition 1996, 3, :o5, 826426800
          tz.transition 1996, 10, :o6, 845179200
          tz.transition 1997, 3, :o5, 859690800
          tz.transition 1997, 10, :o6, 876628800
          tz.transition 1998, 3, :o5, 889930800
          tz.transition 1998, 9, :o6, 906868800
          tz.transition 1999, 4, :o5, 923194800
          tz.transition 1999, 10, :o6, 939528000
          tz.transition 2000, 3, :o5, 952830000
          tz.transition 2000, 10, :o6, 971582400
          tz.transition 2001, 3, :o5, 984279600
          tz.transition 2001, 10, :o6, 1003032000
          tz.transition 2002, 3, :o5, 1015729200
          tz.transition 2002, 10, :o6, 1034481600
          tz.transition 2003, 3, :o5, 1047178800
          tz.transition 2003, 10, :o6, 1065931200
          tz.transition 2004, 3, :o5, 1079233200
          tz.transition 2004, 10, :o6, 1097380800
          tz.transition 2005, 3, :o5, 1110682800
          tz.transition 2005, 10, :o6, 1128830400
          tz.transition 2006, 3, :o5, 1142132400
          tz.transition 2006, 10, :o6, 1160884800
          tz.transition 2007, 3, :o5, 1173582000
          tz.transition 2007, 10, :o6, 1192334400
          tz.transition 2008, 3, :o5, 1206846000
          tz.transition 2008, 10, :o6, 1223784000
          tz.transition 2009, 3, :o5, 1237086000
          tz.transition 2009, 10, :o6, 1255233600
          tz.transition 2010, 4, :o5, 1270350000
          tz.transition 2010, 10, :o6, 1286683200
          tz.transition 2011, 5, :o5, 1304823600
          tz.transition 2011, 8, :o6, 1313899200
          tz.transition 2012, 4, :o5, 1335668400
          tz.transition 2012, 9, :o6, 1346558400
          tz.transition 2013, 3, :o5, 1362884400
          tz.transition 2013, 10, :o6, 1381636800
          tz.transition 2014, 3, :o5, 1394334000
          tz.transition 2014, 10, :o6, 1413086400
          tz.transition 2015, 3, :o5, 1426388400
          tz.transition 2015, 10, :o6, 1444536000
          tz.transition 2016, 3, :o5, 1457838000
          tz.transition 2016, 10, :o6, 1475985600
          tz.transition 2017, 3, :o5, 1489287600
          tz.transition 2017, 10, :o6, 1508040000
          tz.transition 2018, 3, :o5, 1520737200
          tz.transition 2018, 10, :o6, 1539489600
          tz.transition 2019, 3, :o5, 1552186800
          tz.transition 2019, 10, :o6, 1570939200
          tz.transition 2020, 3, :o5, 1584241200
          tz.transition 2020, 10, :o6, 1602388800
          tz.transition 2021, 3, :o5, 1615690800
          tz.transition 2021, 10, :o6, 1633838400
          tz.transition 2022, 3, :o5, 1647140400
          tz.transition 2022, 10, :o6, 1665288000
          tz.transition 2023, 3, :o5, 1678590000
          tz.transition 2023, 10, :o6, 1697342400
          tz.transition 2024, 3, :o5, 1710039600
          tz.transition 2024, 10, :o6, 1728792000
          tz.transition 2025, 3, :o5, 1741489200
          tz.transition 2025, 10, :o6, 1760241600
          tz.transition 2026, 3, :o5, 1773543600
          tz.transition 2026, 10, :o6, 1791691200
          tz.transition 2027, 3, :o5, 1804993200
          tz.transition 2027, 10, :o6, 1823140800
          tz.transition 2028, 3, :o5, 1836442800
          tz.transition 2028, 10, :o6, 1855195200
          tz.transition 2029, 3, :o5, 1867892400
          tz.transition 2029, 10, :o6, 1886644800
          tz.transition 2030, 3, :o5, 1899342000
          tz.transition 2030, 10, :o6, 1918094400
          tz.transition 2031, 3, :o5, 1930791600
          tz.transition 2031, 10, :o6, 1949544000
          tz.transition 2032, 3, :o5, 1962846000
          tz.transition 2032, 10, :o6, 1980993600
          tz.transition 2033, 3, :o5, 1994295600
          tz.transition 2033, 10, :o6, 2012443200
          tz.transition 2034, 3, :o5, 2025745200
          tz.transition 2034, 10, :o6, 2044497600
          tz.transition 2035, 3, :o5, 2057194800
          tz.transition 2035, 10, :o6, 2075947200
          tz.transition 2036, 3, :o5, 2088644400
          tz.transition 2036, 10, :o6, 2107396800
          tz.transition 2037, 3, :o5, 2120698800
          tz.transition 2037, 10, :o6, 2138846400
          tz.transition 2038, 3, :o5, 19723973, 8
          tz.transition 2038, 10, :o6, 7397120, 3
          tz.transition 2039, 3, :o5, 19726885, 8
          tz.transition 2039, 10, :o6, 7398212, 3
          tz.transition 2040, 3, :o5, 19729797, 8
          tz.transition 2040, 10, :o6, 7399325, 3
          tz.transition 2041, 3, :o5, 19732709, 8
          tz.transition 2041, 10, :o6, 7400417, 3
          tz.transition 2042, 3, :o5, 19735621, 8
          tz.transition 2042, 10, :o6, 7401509, 3
          tz.transition 2043, 3, :o5, 19738589, 8
          tz.transition 2043, 10, :o6, 7402601, 3
          tz.transition 2044, 3, :o5, 19741501, 8
          tz.transition 2044, 10, :o6, 7403693, 3
          tz.transition 2045, 3, :o5, 19744413, 8
          tz.transition 2045, 10, :o6, 7404806, 3
          tz.transition 2046, 3, :o5, 19747325, 8
          tz.transition 2046, 10, :o6, 7405898, 3
          tz.transition 2047, 3, :o5, 19750237, 8
          tz.transition 2047, 10, :o6, 7406990, 3
          tz.transition 2048, 3, :o5, 19753205, 8
          tz.transition 2048, 10, :o6, 7408082, 3
          tz.transition 2049, 3, :o5, 19756117, 8
          tz.transition 2049, 10, :o6, 7409174, 3
          tz.transition 2050, 3, :o5, 19759029, 8
        end
      end
    end
  end
end
