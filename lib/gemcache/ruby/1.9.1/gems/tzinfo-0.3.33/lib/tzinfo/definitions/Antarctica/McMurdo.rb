module TZInfo
  module Definitions
    module Antarctica
      module McMurdo
        include TimezoneDefinition
        
        timezone 'Antarctica/McMurdo' do |tz|
          tz.offset :o0, 0, 0, :zzz
          tz.offset :o1, 43200, 0, :NZST
          tz.offset :o2, 43200, 3600, :NZDT
          
          tz.transition 1956, 1, :o1, 4870947, 2
          tz.transition 1974, 11, :o2, 152632800
          tz.transition 1975, 2, :o1, 162309600
          tz.transition 1975, 10, :o2, 183477600
          tz.transition 1976, 3, :o1, 194968800
          tz.transition 1976, 10, :o2, 215532000
          tz.transition 1977, 3, :o1, 226418400
          tz.transition 1977, 10, :o2, 246981600
          tz.transition 1978, 3, :o1, 257868000
          tz.transition 1978, 10, :o2, 278431200
          tz.transition 1979, 3, :o1, 289317600
          tz.transition 1979, 10, :o2, 309880800
          tz.transition 1980, 3, :o1, 320767200
          tz.transition 1980, 10, :o2, 341330400
          tz.transition 1981, 2, :o1, 352216800
          tz.transition 1981, 10, :o2, 372780000
          tz.transition 1982, 3, :o1, 384271200
          tz.transition 1982, 10, :o2, 404834400
          tz.transition 1983, 3, :o1, 415720800
          tz.transition 1983, 10, :o2, 436284000
          tz.transition 1984, 3, :o1, 447170400
          tz.transition 1984, 10, :o2, 467733600
          tz.transition 1985, 3, :o1, 478620000
          tz.transition 1985, 10, :o2, 499183200
          tz.transition 1986, 3, :o1, 510069600
          tz.transition 1986, 10, :o2, 530632800
          tz.transition 1987, 2, :o1, 541519200
          tz.transition 1987, 10, :o2, 562082400
          tz.transition 1988, 3, :o1, 573573600
          tz.transition 1988, 10, :o2, 594136800
          tz.transition 1989, 3, :o1, 605023200
          tz.transition 1989, 10, :o2, 623772000
          tz.transition 1990, 3, :o1, 637682400
          tz.transition 1990, 10, :o2, 655221600
          tz.transition 1991, 3, :o1, 669132000
          tz.transition 1991, 10, :o2, 686671200
          tz.transition 1992, 3, :o1, 700581600
          tz.transition 1992, 10, :o2, 718120800
          tz.transition 1993, 3, :o1, 732636000
          tz.transition 1993, 10, :o2, 749570400
          tz.transition 1994, 3, :o1, 764085600
          tz.transition 1994, 10, :o2, 781020000
          tz.transition 1995, 3, :o1, 795535200
          tz.transition 1995, 9, :o2, 812469600
          tz.transition 1996, 3, :o1, 826984800
          tz.transition 1996, 10, :o2, 844524000
          tz.transition 1997, 3, :o1, 858434400
          tz.transition 1997, 10, :o2, 875973600
          tz.transition 1998, 3, :o1, 889884000
          tz.transition 1998, 10, :o2, 907423200
          tz.transition 1999, 3, :o1, 921938400
          tz.transition 1999, 10, :o2, 938872800
          tz.transition 2000, 3, :o1, 953388000
          tz.transition 2000, 9, :o2, 970322400
          tz.transition 2001, 3, :o1, 984837600
          tz.transition 2001, 10, :o2, 1002376800
          tz.transition 2002, 3, :o1, 1016287200
          tz.transition 2002, 10, :o2, 1033826400
          tz.transition 2003, 3, :o1, 1047736800
          tz.transition 2003, 10, :o2, 1065276000
          tz.transition 2004, 3, :o1, 1079791200
          tz.transition 2004, 10, :o2, 1096725600
          tz.transition 2005, 3, :o1, 1111240800
          tz.transition 2005, 10, :o2, 1128175200
          tz.transition 2006, 3, :o1, 1142690400
          tz.transition 2006, 9, :o2, 1159624800
          tz.transition 2007, 3, :o1, 1174140000
          tz.transition 2007, 9, :o2, 1191074400
          tz.transition 2008, 4, :o1, 1207404000
          tz.transition 2008, 9, :o2, 1222524000
          tz.transition 2009, 4, :o1, 1238853600
          tz.transition 2009, 9, :o2, 1253973600
          tz.transition 2010, 4, :o1, 1270303200
          tz.transition 2010, 9, :o2, 1285423200
          tz.transition 2011, 4, :o1, 1301752800
          tz.transition 2011, 9, :o2, 1316872800
          tz.transition 2012, 3, :o1, 1333202400
          tz.transition 2012, 9, :o2, 1348927200
          tz.transition 2013, 4, :o1, 1365256800
          tz.transition 2013, 9, :o2, 1380376800
          tz.transition 2014, 4, :o1, 1396706400
          tz.transition 2014, 9, :o2, 1411826400
          tz.transition 2015, 4, :o1, 1428156000
          tz.transition 2015, 9, :o2, 1443276000
          tz.transition 2016, 4, :o1, 1459605600
          tz.transition 2016, 9, :o2, 1474725600
          tz.transition 2017, 4, :o1, 1491055200
          tz.transition 2017, 9, :o2, 1506175200
          tz.transition 2018, 3, :o1, 1522504800
          tz.transition 2018, 9, :o2, 1538229600
          tz.transition 2019, 4, :o1, 1554559200
          tz.transition 2019, 9, :o2, 1569679200
          tz.transition 2020, 4, :o1, 1586008800
          tz.transition 2020, 9, :o2, 1601128800
          tz.transition 2021, 4, :o1, 1617458400
          tz.transition 2021, 9, :o2, 1632578400
          tz.transition 2022, 4, :o1, 1648908000
          tz.transition 2022, 9, :o2, 1664028000
          tz.transition 2023, 4, :o1, 1680357600
          tz.transition 2023, 9, :o2, 1695477600
          tz.transition 2024, 4, :o1, 1712412000
          tz.transition 2024, 9, :o2, 1727532000
          tz.transition 2025, 4, :o1, 1743861600
          tz.transition 2025, 9, :o2, 1758981600
          tz.transition 2026, 4, :o1, 1775311200
          tz.transition 2026, 9, :o2, 1790431200
          tz.transition 2027, 4, :o1, 1806760800
          tz.transition 2027, 9, :o2, 1821880800
          tz.transition 2028, 4, :o1, 1838210400
          tz.transition 2028, 9, :o2, 1853330400
          tz.transition 2029, 3, :o1, 1869660000
          tz.transition 2029, 9, :o2, 1885384800
          tz.transition 2030, 4, :o1, 1901714400
          tz.transition 2030, 9, :o2, 1916834400
          tz.transition 2031, 4, :o1, 1933164000
          tz.transition 2031, 9, :o2, 1948284000
          tz.transition 2032, 4, :o1, 1964613600
          tz.transition 2032, 9, :o2, 1979733600
          tz.transition 2033, 4, :o1, 1996063200
          tz.transition 2033, 9, :o2, 2011183200
          tz.transition 2034, 4, :o1, 2027512800
          tz.transition 2034, 9, :o2, 2042632800
          tz.transition 2035, 3, :o1, 2058962400
          tz.transition 2035, 9, :o2, 2074687200
          tz.transition 2036, 4, :o1, 2091016800
          tz.transition 2036, 9, :o2, 2106136800
          tz.transition 2037, 4, :o1, 2122466400
          tz.transition 2037, 9, :o2, 2137586400
          tz.transition 2038, 4, :o1, 29586205, 12
          tz.transition 2038, 9, :o2, 29588305, 12
          tz.transition 2039, 4, :o1, 29590573, 12
          tz.transition 2039, 9, :o2, 29592673, 12
          tz.transition 2040, 3, :o1, 29594941, 12
          tz.transition 2040, 9, :o2, 29597125, 12
          tz.transition 2041, 4, :o1, 29599393, 12
          tz.transition 2041, 9, :o2, 29601493, 12
          tz.transition 2042, 4, :o1, 29603761, 12
          tz.transition 2042, 9, :o2, 29605861, 12
          tz.transition 2043, 4, :o1, 29608129, 12
          tz.transition 2043, 9, :o2, 29610229, 12
          tz.transition 2044, 4, :o1, 29612497, 12
          tz.transition 2044, 9, :o2, 29614597, 12
          tz.transition 2045, 4, :o1, 29616865, 12
          tz.transition 2045, 9, :o2, 29618965, 12
          tz.transition 2046, 3, :o1, 29621233, 12
          tz.transition 2046, 9, :o2, 29623417, 12
          tz.transition 2047, 4, :o1, 29625685, 12
          tz.transition 2047, 9, :o2, 29627785, 12
          tz.transition 2048, 4, :o1, 29630053, 12
          tz.transition 2048, 9, :o2, 29632153, 12
          tz.transition 2049, 4, :o1, 29634421, 12
          tz.transition 2049, 9, :o2, 29636521, 12
          tz.transition 2050, 4, :o1, 29638789, 12
        end
      end
    end
  end
end
