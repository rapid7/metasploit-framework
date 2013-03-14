module TZInfo
  module Definitions
    module America
      module Goose_Bay
        include TimezoneDefinition
        
        timezone 'America/Goose_Bay' do |tz|
          tz.offset :o0, -14500, 0, :LMT
          tz.offset :o1, -12652, 0, :NST
          tz.offset :o2, -12652, 3600, :NDT
          tz.offset :o3, -12600, 0, :NST
          tz.offset :o4, -12600, 3600, :NDT
          tz.offset :o5, -12600, 3600, :NWT
          tz.offset :o6, -12600, 3600, :NPT
          tz.offset :o7, -14400, 0, :AST
          tz.offset :o8, -14400, 3600, :ADT
          tz.offset :o9, -14400, 7200, :ADDT
          
          tz.transition 1884, 1, :o1, 2081528641, 864
          tz.transition 1918, 4, :o2, 52308670963, 21600
          tz.transition 1918, 10, :o1, 52312903663, 21600
          tz.transition 1935, 3, :o3, 52442459563, 21600
          tz.transition 1936, 5, :o4, 116558383, 48
          tz.transition 1936, 10, :o3, 116565437, 48
          tz.transition 1937, 5, :o4, 116575855, 48
          tz.transition 1937, 10, :o3, 116582909, 48
          tz.transition 1938, 5, :o4, 116593327, 48
          tz.transition 1938, 10, :o3, 116600381, 48
          tz.transition 1939, 5, :o4, 116611135, 48
          tz.transition 1939, 10, :o3, 116617853, 48
          tz.transition 1940, 5, :o4, 116628607, 48
          tz.transition 1940, 10, :o3, 116635661, 48
          tz.transition 1941, 5, :o4, 116646079, 48
          tz.transition 1941, 10, :o3, 116653133, 48
          tz.transition 1942, 5, :o5, 116663551, 48
          tz.transition 1945, 8, :o6, 58360379, 24
          tz.transition 1945, 9, :o3, 38907659, 16
          tz.transition 1946, 5, :o4, 116733731, 48
          tz.transition 1946, 10, :o3, 38913595, 16
          tz.transition 1947, 5, :o4, 116751203, 48
          tz.transition 1947, 10, :o3, 38919419, 16
          tz.transition 1948, 5, :o4, 116768675, 48
          tz.transition 1948, 10, :o3, 38925243, 16
          tz.transition 1949, 5, :o4, 116786147, 48
          tz.transition 1949, 10, :o3, 38931067, 16
          tz.transition 1950, 5, :o4, 116803955, 48
          tz.transition 1950, 10, :o3, 38937003, 16
          tz.transition 1951, 4, :o4, 116820755, 48
          tz.transition 1951, 9, :o3, 38942715, 16
          tz.transition 1952, 4, :o4, 116838227, 48
          tz.transition 1952, 9, :o3, 38948539, 16
          tz.transition 1953, 4, :o4, 116855699, 48
          tz.transition 1953, 9, :o3, 38954363, 16
          tz.transition 1954, 4, :o4, 116873171, 48
          tz.transition 1954, 9, :o3, 38960187, 16
          tz.transition 1955, 4, :o4, 116890643, 48
          tz.transition 1955, 9, :o3, 38966011, 16
          tz.transition 1956, 4, :o4, 116908451, 48
          tz.transition 1956, 9, :o3, 38971947, 16
          tz.transition 1957, 4, :o4, 116925923, 48
          tz.transition 1957, 9, :o3, 38977771, 16
          tz.transition 1958, 4, :o4, 116943395, 48
          tz.transition 1958, 9, :o3, 38983595, 16
          tz.transition 1959, 4, :o4, 116960867, 48
          tz.transition 1959, 9, :o3, 38989419, 16
          tz.transition 1960, 4, :o4, 116978339, 48
          tz.transition 1960, 10, :o3, 38995803, 16
          tz.transition 1961, 4, :o4, 116996147, 48
          tz.transition 1961, 10, :o3, 39001627, 16
          tz.transition 1962, 4, :o4, 117013619, 48
          tz.transition 1962, 10, :o3, 39007451, 16
          tz.transition 1963, 4, :o4, 117031091, 48
          tz.transition 1963, 10, :o3, 39013275, 16
          tz.transition 1964, 4, :o4, 117048563, 48
          tz.transition 1964, 10, :o3, 39019099, 16
          tz.transition 1965, 4, :o4, 117066035, 48
          tz.transition 1965, 10, :o3, 39025035, 16
          tz.transition 1966, 3, :o7, 117081587, 48
          tz.transition 1966, 4, :o8, 9756959, 4
          tz.transition 1966, 10, :o7, 58546289, 24
          tz.transition 1967, 4, :o8, 9758443, 4
          tz.transition 1967, 10, :o7, 58555025, 24
          tz.transition 1968, 4, :o8, 9759899, 4
          tz.transition 1968, 10, :o7, 58563761, 24
          tz.transition 1969, 4, :o8, 9761355, 4
          tz.transition 1969, 10, :o7, 58572497, 24
          tz.transition 1970, 4, :o8, 9957600
          tz.transition 1970, 10, :o7, 25678800
          tz.transition 1971, 4, :o8, 41407200
          tz.transition 1971, 10, :o7, 57733200
          tz.transition 1972, 4, :o8, 73461600
          tz.transition 1972, 10, :o7, 89182800
          tz.transition 1973, 4, :o8, 104911200
          tz.transition 1973, 10, :o7, 120632400
          tz.transition 1974, 4, :o8, 136360800
          tz.transition 1974, 10, :o7, 152082000
          tz.transition 1975, 4, :o8, 167810400
          tz.transition 1975, 10, :o7, 183531600
          tz.transition 1976, 4, :o8, 199260000
          tz.transition 1976, 10, :o7, 215586000
          tz.transition 1977, 4, :o8, 230709600
          tz.transition 1977, 10, :o7, 247035600
          tz.transition 1978, 4, :o8, 262764000
          tz.transition 1978, 10, :o7, 278485200
          tz.transition 1979, 4, :o8, 294213600
          tz.transition 1979, 10, :o7, 309934800
          tz.transition 1980, 4, :o8, 325663200
          tz.transition 1980, 10, :o7, 341384400
          tz.transition 1981, 4, :o8, 357112800
          tz.transition 1981, 10, :o7, 372834000
          tz.transition 1982, 4, :o8, 388562400
          tz.transition 1982, 10, :o7, 404888400
          tz.transition 1983, 4, :o8, 420012000
          tz.transition 1983, 10, :o7, 436338000
          tz.transition 1984, 4, :o8, 452066400
          tz.transition 1984, 10, :o7, 467787600
          tz.transition 1985, 4, :o8, 483516000
          tz.transition 1985, 10, :o7, 499237200
          tz.transition 1986, 4, :o8, 514965600
          tz.transition 1986, 10, :o7, 530686800
          tz.transition 1987, 4, :o8, 544593660
          tz.transition 1987, 10, :o7, 562129260
          tz.transition 1988, 4, :o9, 576043260
          tz.transition 1988, 10, :o7, 594180060
          tz.transition 1989, 4, :o8, 607492860
          tz.transition 1989, 10, :o7, 625633260
          tz.transition 1990, 4, :o8, 638942460
          tz.transition 1990, 10, :o7, 657082860
          tz.transition 1991, 4, :o8, 670996860
          tz.transition 1991, 10, :o7, 688532460
          tz.transition 1992, 4, :o8, 702446460
          tz.transition 1992, 10, :o7, 719982060
          tz.transition 1993, 4, :o8, 733896060
          tz.transition 1993, 10, :o7, 752036460
          tz.transition 1994, 4, :o8, 765345660
          tz.transition 1994, 10, :o7, 783486060
          tz.transition 1995, 4, :o8, 796795260
          tz.transition 1995, 10, :o7, 814935660
          tz.transition 1996, 4, :o8, 828849660
          tz.transition 1996, 10, :o7, 846385260
          tz.transition 1997, 4, :o8, 860299260
          tz.transition 1997, 10, :o7, 877834860
          tz.transition 1998, 4, :o8, 891748860
          tz.transition 1998, 10, :o7, 909284460
          tz.transition 1999, 4, :o8, 923198460
          tz.transition 1999, 10, :o7, 941338860
          tz.transition 2000, 4, :o8, 954648060
          tz.transition 2000, 10, :o7, 972788460
          tz.transition 2001, 4, :o8, 986097660
          tz.transition 2001, 10, :o7, 1004238060
          tz.transition 2002, 4, :o8, 1018152060
          tz.transition 2002, 10, :o7, 1035687660
          tz.transition 2003, 4, :o8, 1049601660
          tz.transition 2003, 10, :o7, 1067137260
          tz.transition 2004, 4, :o8, 1081051260
          tz.transition 2004, 10, :o7, 1099191660
          tz.transition 2005, 4, :o8, 1112500860
          tz.transition 2005, 10, :o7, 1130641260
          tz.transition 2006, 4, :o8, 1143950460
          tz.transition 2006, 10, :o7, 1162090860
          tz.transition 2007, 3, :o8, 1173585660
          tz.transition 2007, 11, :o7, 1194145260
          tz.transition 2008, 3, :o8, 1205035260
          tz.transition 2008, 11, :o7, 1225594860
          tz.transition 2009, 3, :o8, 1236484860
          tz.transition 2009, 11, :o7, 1257044460
          tz.transition 2010, 3, :o8, 1268539260
          tz.transition 2010, 11, :o7, 1289098860
          tz.transition 2011, 3, :o8, 1299988860
          tz.transition 2011, 11, :o7, 1320555600
          tz.transition 2012, 3, :o8, 1331445600
          tz.transition 2012, 11, :o7, 1352005200
          tz.transition 2013, 3, :o8, 1362895200
          tz.transition 2013, 11, :o7, 1383454800
          tz.transition 2014, 3, :o8, 1394344800
          tz.transition 2014, 11, :o7, 1414904400
          tz.transition 2015, 3, :o8, 1425794400
          tz.transition 2015, 11, :o7, 1446354000
          tz.transition 2016, 3, :o8, 1457848800
          tz.transition 2016, 11, :o7, 1478408400
          tz.transition 2017, 3, :o8, 1489298400
          tz.transition 2017, 11, :o7, 1509858000
          tz.transition 2018, 3, :o8, 1520748000
          tz.transition 2018, 11, :o7, 1541307600
          tz.transition 2019, 3, :o8, 1552197600
          tz.transition 2019, 11, :o7, 1572757200
          tz.transition 2020, 3, :o8, 1583647200
          tz.transition 2020, 11, :o7, 1604206800
          tz.transition 2021, 3, :o8, 1615701600
          tz.transition 2021, 11, :o7, 1636261200
          tz.transition 2022, 3, :o8, 1647151200
          tz.transition 2022, 11, :o7, 1667710800
          tz.transition 2023, 3, :o8, 1678600800
          tz.transition 2023, 11, :o7, 1699160400
          tz.transition 2024, 3, :o8, 1710050400
          tz.transition 2024, 11, :o7, 1730610000
          tz.transition 2025, 3, :o8, 1741500000
          tz.transition 2025, 11, :o7, 1762059600
          tz.transition 2026, 3, :o8, 1772949600
          tz.transition 2026, 11, :o7, 1793509200
          tz.transition 2027, 3, :o8, 1805004000
          tz.transition 2027, 11, :o7, 1825563600
          tz.transition 2028, 3, :o8, 1836453600
          tz.transition 2028, 11, :o7, 1857013200
          tz.transition 2029, 3, :o8, 1867903200
          tz.transition 2029, 11, :o7, 1888462800
          tz.transition 2030, 3, :o8, 1899352800
          tz.transition 2030, 11, :o7, 1919912400
          tz.transition 2031, 3, :o8, 1930802400
          tz.transition 2031, 11, :o7, 1951362000
          tz.transition 2032, 3, :o8, 1962856800
          tz.transition 2032, 11, :o7, 1983416400
          tz.transition 2033, 3, :o8, 1994306400
          tz.transition 2033, 11, :o7, 2014866000
          tz.transition 2034, 3, :o8, 2025756000
          tz.transition 2034, 11, :o7, 2046315600
          tz.transition 2035, 3, :o8, 2057205600
          tz.transition 2035, 11, :o7, 2077765200
          tz.transition 2036, 3, :o8, 2088655200
          tz.transition 2036, 11, :o7, 2109214800
          tz.transition 2037, 3, :o8, 2120104800
          tz.transition 2037, 11, :o7, 2140664400
          tz.transition 2038, 3, :o8, 9861987, 4
          tz.transition 2038, 11, :o7, 59177633, 24
          tz.transition 2039, 3, :o8, 9863443, 4
          tz.transition 2039, 11, :o7, 59186369, 24
          tz.transition 2040, 3, :o8, 9864899, 4
          tz.transition 2040, 11, :o7, 59195105, 24
          tz.transition 2041, 3, :o8, 9866355, 4
          tz.transition 2041, 11, :o7, 59203841, 24
          tz.transition 2042, 3, :o8, 9867811, 4
          tz.transition 2042, 11, :o7, 59212577, 24
          tz.transition 2043, 3, :o8, 9869267, 4
          tz.transition 2043, 11, :o7, 59221313, 24
          tz.transition 2044, 3, :o8, 9870751, 4
          tz.transition 2044, 11, :o7, 59230217, 24
          tz.transition 2045, 3, :o8, 9872207, 4
          tz.transition 2045, 11, :o7, 59238953, 24
          tz.transition 2046, 3, :o8, 9873663, 4
          tz.transition 2046, 11, :o7, 59247689, 24
          tz.transition 2047, 3, :o8, 9875119, 4
          tz.transition 2047, 11, :o7, 59256425, 24
          tz.transition 2048, 3, :o8, 9876575, 4
          tz.transition 2048, 11, :o7, 59265161, 24
          tz.transition 2049, 3, :o8, 9878059, 4
          tz.transition 2049, 11, :o7, 59274065, 24
          tz.transition 2050, 3, :o8, 9879515, 4
          tz.transition 2050, 11, :o7, 59282801, 24
        end
      end
    end
  end
end
