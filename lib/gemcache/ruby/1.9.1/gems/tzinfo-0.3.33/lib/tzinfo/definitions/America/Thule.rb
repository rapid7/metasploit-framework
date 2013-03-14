module TZInfo
  module Definitions
    module America
      module Thule
        include TimezoneDefinition
        
        timezone 'America/Thule' do |tz|
          tz.offset :o0, -16508, 0, :LMT
          tz.offset :o1, -14400, 0, :AST
          tz.offset :o2, -14400, 3600, :ADT
          
          tz.transition 1916, 7, :o1, 52295170127, 21600
          tz.transition 1991, 3, :o2, 670399200
          tz.transition 1991, 9, :o1, 686120400
          tz.transition 1992, 3, :o2, 701848800
          tz.transition 1992, 9, :o1, 717570000
          tz.transition 1993, 4, :o2, 733903200
          tz.transition 1993, 10, :o1, 752043600
          tz.transition 1994, 4, :o2, 765352800
          tz.transition 1994, 10, :o1, 783493200
          tz.transition 1995, 4, :o2, 796802400
          tz.transition 1995, 10, :o1, 814942800
          tz.transition 1996, 4, :o2, 828856800
          tz.transition 1996, 10, :o1, 846392400
          tz.transition 1997, 4, :o2, 860306400
          tz.transition 1997, 10, :o1, 877842000
          tz.transition 1998, 4, :o2, 891756000
          tz.transition 1998, 10, :o1, 909291600
          tz.transition 1999, 4, :o2, 923205600
          tz.transition 1999, 10, :o1, 941346000
          tz.transition 2000, 4, :o2, 954655200
          tz.transition 2000, 10, :o1, 972795600
          tz.transition 2001, 4, :o2, 986104800
          tz.transition 2001, 10, :o1, 1004245200
          tz.transition 2002, 4, :o2, 1018159200
          tz.transition 2002, 10, :o1, 1035694800
          tz.transition 2003, 4, :o2, 1049608800
          tz.transition 2003, 10, :o1, 1067144400
          tz.transition 2004, 4, :o2, 1081058400
          tz.transition 2004, 10, :o1, 1099198800
          tz.transition 2005, 4, :o2, 1112508000
          tz.transition 2005, 10, :o1, 1130648400
          tz.transition 2006, 4, :o2, 1143957600
          tz.transition 2006, 10, :o1, 1162098000
          tz.transition 2007, 3, :o2, 1173592800
          tz.transition 2007, 11, :o1, 1194152400
          tz.transition 2008, 3, :o2, 1205042400
          tz.transition 2008, 11, :o1, 1225602000
          tz.transition 2009, 3, :o2, 1236492000
          tz.transition 2009, 11, :o1, 1257051600
          tz.transition 2010, 3, :o2, 1268546400
          tz.transition 2010, 11, :o1, 1289106000
          tz.transition 2011, 3, :o2, 1299996000
          tz.transition 2011, 11, :o1, 1320555600
          tz.transition 2012, 3, :o2, 1331445600
          tz.transition 2012, 11, :o1, 1352005200
          tz.transition 2013, 3, :o2, 1362895200
          tz.transition 2013, 11, :o1, 1383454800
          tz.transition 2014, 3, :o2, 1394344800
          tz.transition 2014, 11, :o1, 1414904400
          tz.transition 2015, 3, :o2, 1425794400
          tz.transition 2015, 11, :o1, 1446354000
          tz.transition 2016, 3, :o2, 1457848800
          tz.transition 2016, 11, :o1, 1478408400
          tz.transition 2017, 3, :o2, 1489298400
          tz.transition 2017, 11, :o1, 1509858000
          tz.transition 2018, 3, :o2, 1520748000
          tz.transition 2018, 11, :o1, 1541307600
          tz.transition 2019, 3, :o2, 1552197600
          tz.transition 2019, 11, :o1, 1572757200
          tz.transition 2020, 3, :o2, 1583647200
          tz.transition 2020, 11, :o1, 1604206800
          tz.transition 2021, 3, :o2, 1615701600
          tz.transition 2021, 11, :o1, 1636261200
          tz.transition 2022, 3, :o2, 1647151200
          tz.transition 2022, 11, :o1, 1667710800
          tz.transition 2023, 3, :o2, 1678600800
          tz.transition 2023, 11, :o1, 1699160400
          tz.transition 2024, 3, :o2, 1710050400
          tz.transition 2024, 11, :o1, 1730610000
          tz.transition 2025, 3, :o2, 1741500000
          tz.transition 2025, 11, :o1, 1762059600
          tz.transition 2026, 3, :o2, 1772949600
          tz.transition 2026, 11, :o1, 1793509200
          tz.transition 2027, 3, :o2, 1805004000
          tz.transition 2027, 11, :o1, 1825563600
          tz.transition 2028, 3, :o2, 1836453600
          tz.transition 2028, 11, :o1, 1857013200
          tz.transition 2029, 3, :o2, 1867903200
          tz.transition 2029, 11, :o1, 1888462800
          tz.transition 2030, 3, :o2, 1899352800
          tz.transition 2030, 11, :o1, 1919912400
          tz.transition 2031, 3, :o2, 1930802400
          tz.transition 2031, 11, :o1, 1951362000
          tz.transition 2032, 3, :o2, 1962856800
          tz.transition 2032, 11, :o1, 1983416400
          tz.transition 2033, 3, :o2, 1994306400
          tz.transition 2033, 11, :o1, 2014866000
          tz.transition 2034, 3, :o2, 2025756000
          tz.transition 2034, 11, :o1, 2046315600
          tz.transition 2035, 3, :o2, 2057205600
          tz.transition 2035, 11, :o1, 2077765200
          tz.transition 2036, 3, :o2, 2088655200
          tz.transition 2036, 11, :o1, 2109214800
          tz.transition 2037, 3, :o2, 2120104800
          tz.transition 2037, 11, :o1, 2140664400
          tz.transition 2038, 3, :o2, 9861987, 4
          tz.transition 2038, 11, :o1, 59177633, 24
          tz.transition 2039, 3, :o2, 9863443, 4
          tz.transition 2039, 11, :o1, 59186369, 24
          tz.transition 2040, 3, :o2, 9864899, 4
          tz.transition 2040, 11, :o1, 59195105, 24
          tz.transition 2041, 3, :o2, 9866355, 4
          tz.transition 2041, 11, :o1, 59203841, 24
          tz.transition 2042, 3, :o2, 9867811, 4
          tz.transition 2042, 11, :o1, 59212577, 24
          tz.transition 2043, 3, :o2, 9869267, 4
          tz.transition 2043, 11, :o1, 59221313, 24
          tz.transition 2044, 3, :o2, 9870751, 4
          tz.transition 2044, 11, :o1, 59230217, 24
          tz.transition 2045, 3, :o2, 9872207, 4
          tz.transition 2045, 11, :o1, 59238953, 24
          tz.transition 2046, 3, :o2, 9873663, 4
          tz.transition 2046, 11, :o1, 59247689, 24
          tz.transition 2047, 3, :o2, 9875119, 4
          tz.transition 2047, 11, :o1, 59256425, 24
          tz.transition 2048, 3, :o2, 9876575, 4
          tz.transition 2048, 11, :o1, 59265161, 24
          tz.transition 2049, 3, :o2, 9878059, 4
          tz.transition 2049, 11, :o1, 59274065, 24
          tz.transition 2050, 3, :o2, 9879515, 4
          tz.transition 2050, 11, :o1, 59282801, 24
        end
      end
    end
  end
end
