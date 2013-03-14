module TZInfo
  module Definitions
    module EST5EDT
      include TimezoneDefinition
      
      timezone 'EST5EDT' do |tz|
        tz.offset :o0, -18000, 0, :EST
        tz.offset :o1, -18000, 3600, :EDT
        tz.offset :o2, -18000, 3600, :EWT
        tz.offset :o3, -18000, 3600, :EPT
        
        tz.transition 1918, 3, :o1, 58120411, 24
        tz.transition 1918, 10, :o0, 9687575, 4
        tz.transition 1919, 3, :o1, 58129147, 24
        tz.transition 1919, 10, :o0, 9689031, 4
        tz.transition 1942, 2, :o2, 58329595, 24
        tz.transition 1945, 8, :o3, 58360379, 24
        tz.transition 1945, 9, :o0, 9726915, 4
        tz.transition 1967, 4, :o1, 58550659, 24
        tz.transition 1967, 10, :o0, 9759171, 4
        tz.transition 1968, 4, :o1, 58559395, 24
        tz.transition 1968, 10, :o0, 9760627, 4
        tz.transition 1969, 4, :o1, 58568131, 24
        tz.transition 1969, 10, :o0, 9762083, 4
        tz.transition 1970, 4, :o1, 9961200
        tz.transition 1970, 10, :o0, 25682400
        tz.transition 1971, 4, :o1, 41410800
        tz.transition 1971, 10, :o0, 57736800
        tz.transition 1972, 4, :o1, 73465200
        tz.transition 1972, 10, :o0, 89186400
        tz.transition 1973, 4, :o1, 104914800
        tz.transition 1973, 10, :o0, 120636000
        tz.transition 1974, 1, :o1, 126687600
        tz.transition 1974, 10, :o0, 152085600
        tz.transition 1975, 2, :o1, 162370800
        tz.transition 1975, 10, :o0, 183535200
        tz.transition 1976, 4, :o1, 199263600
        tz.transition 1976, 10, :o0, 215589600
        tz.transition 1977, 4, :o1, 230713200
        tz.transition 1977, 10, :o0, 247039200
        tz.transition 1978, 4, :o1, 262767600
        tz.transition 1978, 10, :o0, 278488800
        tz.transition 1979, 4, :o1, 294217200
        tz.transition 1979, 10, :o0, 309938400
        tz.transition 1980, 4, :o1, 325666800
        tz.transition 1980, 10, :o0, 341388000
        tz.transition 1981, 4, :o1, 357116400
        tz.transition 1981, 10, :o0, 372837600
        tz.transition 1982, 4, :o1, 388566000
        tz.transition 1982, 10, :o0, 404892000
        tz.transition 1983, 4, :o1, 420015600
        tz.transition 1983, 10, :o0, 436341600
        tz.transition 1984, 4, :o1, 452070000
        tz.transition 1984, 10, :o0, 467791200
        tz.transition 1985, 4, :o1, 483519600
        tz.transition 1985, 10, :o0, 499240800
        tz.transition 1986, 4, :o1, 514969200
        tz.transition 1986, 10, :o0, 530690400
        tz.transition 1987, 4, :o1, 544604400
        tz.transition 1987, 10, :o0, 562140000
        tz.transition 1988, 4, :o1, 576054000
        tz.transition 1988, 10, :o0, 594194400
        tz.transition 1989, 4, :o1, 607503600
        tz.transition 1989, 10, :o0, 625644000
        tz.transition 1990, 4, :o1, 638953200
        tz.transition 1990, 10, :o0, 657093600
        tz.transition 1991, 4, :o1, 671007600
        tz.transition 1991, 10, :o0, 688543200
        tz.transition 1992, 4, :o1, 702457200
        tz.transition 1992, 10, :o0, 719992800
        tz.transition 1993, 4, :o1, 733906800
        tz.transition 1993, 10, :o0, 752047200
        tz.transition 1994, 4, :o1, 765356400
        tz.transition 1994, 10, :o0, 783496800
        tz.transition 1995, 4, :o1, 796806000
        tz.transition 1995, 10, :o0, 814946400
        tz.transition 1996, 4, :o1, 828860400
        tz.transition 1996, 10, :o0, 846396000
        tz.transition 1997, 4, :o1, 860310000
        tz.transition 1997, 10, :o0, 877845600
        tz.transition 1998, 4, :o1, 891759600
        tz.transition 1998, 10, :o0, 909295200
        tz.transition 1999, 4, :o1, 923209200
        tz.transition 1999, 10, :o0, 941349600
        tz.transition 2000, 4, :o1, 954658800
        tz.transition 2000, 10, :o0, 972799200
        tz.transition 2001, 4, :o1, 986108400
        tz.transition 2001, 10, :o0, 1004248800
        tz.transition 2002, 4, :o1, 1018162800
        tz.transition 2002, 10, :o0, 1035698400
        tz.transition 2003, 4, :o1, 1049612400
        tz.transition 2003, 10, :o0, 1067148000
        tz.transition 2004, 4, :o1, 1081062000
        tz.transition 2004, 10, :o0, 1099202400
        tz.transition 2005, 4, :o1, 1112511600
        tz.transition 2005, 10, :o0, 1130652000
        tz.transition 2006, 4, :o1, 1143961200
        tz.transition 2006, 10, :o0, 1162101600
        tz.transition 2007, 3, :o1, 1173596400
        tz.transition 2007, 11, :o0, 1194156000
        tz.transition 2008, 3, :o1, 1205046000
        tz.transition 2008, 11, :o0, 1225605600
        tz.transition 2009, 3, :o1, 1236495600
        tz.transition 2009, 11, :o0, 1257055200
        tz.transition 2010, 3, :o1, 1268550000
        tz.transition 2010, 11, :o0, 1289109600
        tz.transition 2011, 3, :o1, 1299999600
        tz.transition 2011, 11, :o0, 1320559200
        tz.transition 2012, 3, :o1, 1331449200
        tz.transition 2012, 11, :o0, 1352008800
        tz.transition 2013, 3, :o1, 1362898800
        tz.transition 2013, 11, :o0, 1383458400
        tz.transition 2014, 3, :o1, 1394348400
        tz.transition 2014, 11, :o0, 1414908000
        tz.transition 2015, 3, :o1, 1425798000
        tz.transition 2015, 11, :o0, 1446357600
        tz.transition 2016, 3, :o1, 1457852400
        tz.transition 2016, 11, :o0, 1478412000
        tz.transition 2017, 3, :o1, 1489302000
        tz.transition 2017, 11, :o0, 1509861600
        tz.transition 2018, 3, :o1, 1520751600
        tz.transition 2018, 11, :o0, 1541311200
        tz.transition 2019, 3, :o1, 1552201200
        tz.transition 2019, 11, :o0, 1572760800
        tz.transition 2020, 3, :o1, 1583650800
        tz.transition 2020, 11, :o0, 1604210400
        tz.transition 2021, 3, :o1, 1615705200
        tz.transition 2021, 11, :o0, 1636264800
        tz.transition 2022, 3, :o1, 1647154800
        tz.transition 2022, 11, :o0, 1667714400
        tz.transition 2023, 3, :o1, 1678604400
        tz.transition 2023, 11, :o0, 1699164000
        tz.transition 2024, 3, :o1, 1710054000
        tz.transition 2024, 11, :o0, 1730613600
        tz.transition 2025, 3, :o1, 1741503600
        tz.transition 2025, 11, :o0, 1762063200
        tz.transition 2026, 3, :o1, 1772953200
        tz.transition 2026, 11, :o0, 1793512800
        tz.transition 2027, 3, :o1, 1805007600
        tz.transition 2027, 11, :o0, 1825567200
        tz.transition 2028, 3, :o1, 1836457200
        tz.transition 2028, 11, :o0, 1857016800
        tz.transition 2029, 3, :o1, 1867906800
        tz.transition 2029, 11, :o0, 1888466400
        tz.transition 2030, 3, :o1, 1899356400
        tz.transition 2030, 11, :o0, 1919916000
        tz.transition 2031, 3, :o1, 1930806000
        tz.transition 2031, 11, :o0, 1951365600
        tz.transition 2032, 3, :o1, 1962860400
        tz.transition 2032, 11, :o0, 1983420000
        tz.transition 2033, 3, :o1, 1994310000
        tz.transition 2033, 11, :o0, 2014869600
        tz.transition 2034, 3, :o1, 2025759600
        tz.transition 2034, 11, :o0, 2046319200
        tz.transition 2035, 3, :o1, 2057209200
        tz.transition 2035, 11, :o0, 2077768800
        tz.transition 2036, 3, :o1, 2088658800
        tz.transition 2036, 11, :o0, 2109218400
        tz.transition 2037, 3, :o1, 2120108400
        tz.transition 2037, 11, :o0, 2140668000
        tz.transition 2038, 3, :o1, 59171923, 24
        tz.transition 2038, 11, :o0, 9862939, 4
        tz.transition 2039, 3, :o1, 59180659, 24
        tz.transition 2039, 11, :o0, 9864395, 4
        tz.transition 2040, 3, :o1, 59189395, 24
        tz.transition 2040, 11, :o0, 9865851, 4
        tz.transition 2041, 3, :o1, 59198131, 24
        tz.transition 2041, 11, :o0, 9867307, 4
        tz.transition 2042, 3, :o1, 59206867, 24
        tz.transition 2042, 11, :o0, 9868763, 4
        tz.transition 2043, 3, :o1, 59215603, 24
        tz.transition 2043, 11, :o0, 9870219, 4
        tz.transition 2044, 3, :o1, 59224507, 24
        tz.transition 2044, 11, :o0, 9871703, 4
        tz.transition 2045, 3, :o1, 59233243, 24
        tz.transition 2045, 11, :o0, 9873159, 4
        tz.transition 2046, 3, :o1, 59241979, 24
        tz.transition 2046, 11, :o0, 9874615, 4
        tz.transition 2047, 3, :o1, 59250715, 24
        tz.transition 2047, 11, :o0, 9876071, 4
        tz.transition 2048, 3, :o1, 59259451, 24
        tz.transition 2048, 11, :o0, 9877527, 4
        tz.transition 2049, 3, :o1, 59268355, 24
        tz.transition 2049, 11, :o0, 9879011, 4
        tz.transition 2050, 3, :o1, 59277091, 24
        tz.transition 2050, 11, :o0, 9880467, 4
      end
    end
  end
end
