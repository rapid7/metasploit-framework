module TZInfo
  module Definitions
    module America
      module Pangnirtung
        include TimezoneDefinition
        
        timezone 'America/Pangnirtung' do |tz|
          tz.offset :o0, 0, 0, :zzz
          tz.offset :o1, -14400, 0, :AST
          tz.offset :o2, -14400, 3600, :AWT
          tz.offset :o3, -14400, 3600, :APT
          tz.offset :o4, -14400, 7200, :ADDT
          tz.offset :o5, -14400, 3600, :ADT
          tz.offset :o6, -18000, 3600, :EDT
          tz.offset :o7, -18000, 0, :EST
          tz.offset :o8, -21600, 0, :CST
          tz.offset :o9, -21600, 3600, :CDT
          
          tz.transition 1921, 1, :o1, 4845381, 2
          tz.transition 1942, 2, :o2, 9721599, 4
          tz.transition 1945, 8, :o3, 58360379, 24
          tz.transition 1945, 9, :o1, 58361489, 24
          tz.transition 1965, 4, :o4, 7316627, 3
          tz.transition 1965, 10, :o1, 7317194, 3
          tz.transition 1980, 4, :o5, 325663200
          tz.transition 1980, 10, :o1, 341384400
          tz.transition 1981, 4, :o5, 357112800
          tz.transition 1981, 10, :o1, 372834000
          tz.transition 1982, 4, :o5, 388562400
          tz.transition 1982, 10, :o1, 404888400
          tz.transition 1983, 4, :o5, 420012000
          tz.transition 1983, 10, :o1, 436338000
          tz.transition 1984, 4, :o5, 452066400
          tz.transition 1984, 10, :o1, 467787600
          tz.transition 1985, 4, :o5, 483516000
          tz.transition 1985, 10, :o1, 499237200
          tz.transition 1986, 4, :o5, 514965600
          tz.transition 1986, 10, :o1, 530686800
          tz.transition 1987, 4, :o5, 544600800
          tz.transition 1987, 10, :o1, 562136400
          tz.transition 1988, 4, :o5, 576050400
          tz.transition 1988, 10, :o1, 594190800
          tz.transition 1989, 4, :o5, 607500000
          tz.transition 1989, 10, :o1, 625640400
          tz.transition 1990, 4, :o5, 638949600
          tz.transition 1990, 10, :o1, 657090000
          tz.transition 1991, 4, :o5, 671004000
          tz.transition 1991, 10, :o1, 688539600
          tz.transition 1992, 4, :o5, 702453600
          tz.transition 1992, 10, :o1, 719989200
          tz.transition 1993, 4, :o5, 733903200
          tz.transition 1993, 10, :o1, 752043600
          tz.transition 1994, 4, :o5, 765352800
          tz.transition 1994, 10, :o1, 783493200
          tz.transition 1995, 4, :o6, 796802400
          tz.transition 1995, 10, :o7, 814946400
          tz.transition 1996, 4, :o6, 828860400
          tz.transition 1996, 10, :o7, 846396000
          tz.transition 1997, 4, :o6, 860310000
          tz.transition 1997, 10, :o7, 877845600
          tz.transition 1998, 4, :o6, 891759600
          tz.transition 1998, 10, :o7, 909295200
          tz.transition 1999, 4, :o6, 923209200
          tz.transition 1999, 10, :o8, 941349600
          tz.transition 2000, 4, :o9, 954662400
          tz.transition 2000, 10, :o7, 972802800
          tz.transition 2001, 4, :o6, 986108400
          tz.transition 2001, 10, :o7, 1004248800
          tz.transition 2002, 4, :o6, 1018162800
          tz.transition 2002, 10, :o7, 1035698400
          tz.transition 2003, 4, :o6, 1049612400
          tz.transition 2003, 10, :o7, 1067148000
          tz.transition 2004, 4, :o6, 1081062000
          tz.transition 2004, 10, :o7, 1099202400
          tz.transition 2005, 4, :o6, 1112511600
          tz.transition 2005, 10, :o7, 1130652000
          tz.transition 2006, 4, :o6, 1143961200
          tz.transition 2006, 10, :o7, 1162101600
          tz.transition 2007, 3, :o6, 1173596400
          tz.transition 2007, 11, :o7, 1194156000
          tz.transition 2008, 3, :o6, 1205046000
          tz.transition 2008, 11, :o7, 1225605600
          tz.transition 2009, 3, :o6, 1236495600
          tz.transition 2009, 11, :o7, 1257055200
          tz.transition 2010, 3, :o6, 1268550000
          tz.transition 2010, 11, :o7, 1289109600
          tz.transition 2011, 3, :o6, 1299999600
          tz.transition 2011, 11, :o7, 1320559200
          tz.transition 2012, 3, :o6, 1331449200
          tz.transition 2012, 11, :o7, 1352008800
          tz.transition 2013, 3, :o6, 1362898800
          tz.transition 2013, 11, :o7, 1383458400
          tz.transition 2014, 3, :o6, 1394348400
          tz.transition 2014, 11, :o7, 1414908000
          tz.transition 2015, 3, :o6, 1425798000
          tz.transition 2015, 11, :o7, 1446357600
          tz.transition 2016, 3, :o6, 1457852400
          tz.transition 2016, 11, :o7, 1478412000
          tz.transition 2017, 3, :o6, 1489302000
          tz.transition 2017, 11, :o7, 1509861600
          tz.transition 2018, 3, :o6, 1520751600
          tz.transition 2018, 11, :o7, 1541311200
          tz.transition 2019, 3, :o6, 1552201200
          tz.transition 2019, 11, :o7, 1572760800
          tz.transition 2020, 3, :o6, 1583650800
          tz.transition 2020, 11, :o7, 1604210400
          tz.transition 2021, 3, :o6, 1615705200
          tz.transition 2021, 11, :o7, 1636264800
          tz.transition 2022, 3, :o6, 1647154800
          tz.transition 2022, 11, :o7, 1667714400
          tz.transition 2023, 3, :o6, 1678604400
          tz.transition 2023, 11, :o7, 1699164000
          tz.transition 2024, 3, :o6, 1710054000
          tz.transition 2024, 11, :o7, 1730613600
          tz.transition 2025, 3, :o6, 1741503600
          tz.transition 2025, 11, :o7, 1762063200
          tz.transition 2026, 3, :o6, 1772953200
          tz.transition 2026, 11, :o7, 1793512800
          tz.transition 2027, 3, :o6, 1805007600
          tz.transition 2027, 11, :o7, 1825567200
          tz.transition 2028, 3, :o6, 1836457200
          tz.transition 2028, 11, :o7, 1857016800
          tz.transition 2029, 3, :o6, 1867906800
          tz.transition 2029, 11, :o7, 1888466400
          tz.transition 2030, 3, :o6, 1899356400
          tz.transition 2030, 11, :o7, 1919916000
          tz.transition 2031, 3, :o6, 1930806000
          tz.transition 2031, 11, :o7, 1951365600
          tz.transition 2032, 3, :o6, 1962860400
          tz.transition 2032, 11, :o7, 1983420000
          tz.transition 2033, 3, :o6, 1994310000
          tz.transition 2033, 11, :o7, 2014869600
          tz.transition 2034, 3, :o6, 2025759600
          tz.transition 2034, 11, :o7, 2046319200
          tz.transition 2035, 3, :o6, 2057209200
          tz.transition 2035, 11, :o7, 2077768800
          tz.transition 2036, 3, :o6, 2088658800
          tz.transition 2036, 11, :o7, 2109218400
          tz.transition 2037, 3, :o6, 2120108400
          tz.transition 2037, 11, :o7, 2140668000
          tz.transition 2038, 3, :o6, 59171923, 24
          tz.transition 2038, 11, :o7, 9862939, 4
          tz.transition 2039, 3, :o6, 59180659, 24
          tz.transition 2039, 11, :o7, 9864395, 4
          tz.transition 2040, 3, :o6, 59189395, 24
          tz.transition 2040, 11, :o7, 9865851, 4
          tz.transition 2041, 3, :o6, 59198131, 24
          tz.transition 2041, 11, :o7, 9867307, 4
          tz.transition 2042, 3, :o6, 59206867, 24
          tz.transition 2042, 11, :o7, 9868763, 4
          tz.transition 2043, 3, :o6, 59215603, 24
          tz.transition 2043, 11, :o7, 9870219, 4
          tz.transition 2044, 3, :o6, 59224507, 24
          tz.transition 2044, 11, :o7, 9871703, 4
          tz.transition 2045, 3, :o6, 59233243, 24
          tz.transition 2045, 11, :o7, 9873159, 4
          tz.transition 2046, 3, :o6, 59241979, 24
          tz.transition 2046, 11, :o7, 9874615, 4
          tz.transition 2047, 3, :o6, 59250715, 24
          tz.transition 2047, 11, :o7, 9876071, 4
          tz.transition 2048, 3, :o6, 59259451, 24
          tz.transition 2048, 11, :o7, 9877527, 4
          tz.transition 2049, 3, :o6, 59268355, 24
          tz.transition 2049, 11, :o7, 9879011, 4
          tz.transition 2050, 3, :o6, 59277091, 24
          tz.transition 2050, 11, :o7, 9880467, 4
        end
      end
    end
  end
end
