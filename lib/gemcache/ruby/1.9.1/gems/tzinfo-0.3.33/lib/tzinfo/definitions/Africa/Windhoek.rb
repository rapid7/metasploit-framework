module TZInfo
  module Definitions
    module Africa
      module Windhoek
        include TimezoneDefinition
        
        timezone 'Africa/Windhoek' do |tz|
          tz.offset :o0, 4104, 0, :LMT
          tz.offset :o1, 5400, 0, :SWAT
          tz.offset :o2, 7200, 0, :SAST
          tz.offset :o3, 7200, 3600, :SAST
          tz.offset :o4, 7200, 0, :CAT
          tz.offset :o5, 3600, 0, :WAT
          tz.offset :o6, 3600, 3600, :WAST
          
          tz.transition 1892, 2, :o1, 964854581, 400
          tz.transition 1903, 2, :o2, 38658791, 16
          tz.transition 1942, 9, :o3, 4861245, 2
          tz.transition 1943, 3, :o2, 58339307, 24
          tz.transition 1990, 3, :o4, 637970400
          tz.transition 1994, 4, :o5, 765324000
          tz.transition 1994, 9, :o6, 778640400
          tz.transition 1995, 4, :o5, 796780800
          tz.transition 1995, 9, :o6, 810090000
          tz.transition 1996, 4, :o5, 828835200
          tz.transition 1996, 9, :o6, 841539600
          tz.transition 1997, 4, :o5, 860284800
          tz.transition 1997, 9, :o6, 873594000
          tz.transition 1998, 4, :o5, 891734400
          tz.transition 1998, 9, :o6, 905043600
          tz.transition 1999, 4, :o5, 923184000
          tz.transition 1999, 9, :o6, 936493200
          tz.transition 2000, 4, :o5, 954633600
          tz.transition 2000, 9, :o6, 967942800
          tz.transition 2001, 4, :o5, 986083200
          tz.transition 2001, 9, :o6, 999392400
          tz.transition 2002, 4, :o5, 1018137600
          tz.transition 2002, 9, :o6, 1030842000
          tz.transition 2003, 4, :o5, 1049587200
          tz.transition 2003, 9, :o6, 1062896400
          tz.transition 2004, 4, :o5, 1081036800
          tz.transition 2004, 9, :o6, 1094346000
          tz.transition 2005, 4, :o5, 1112486400
          tz.transition 2005, 9, :o6, 1125795600
          tz.transition 2006, 4, :o5, 1143936000
          tz.transition 2006, 9, :o6, 1157245200
          tz.transition 2007, 4, :o5, 1175385600
          tz.transition 2007, 9, :o6, 1188694800
          tz.transition 2008, 4, :o5, 1207440000
          tz.transition 2008, 9, :o6, 1220749200
          tz.transition 2009, 4, :o5, 1238889600
          tz.transition 2009, 9, :o6, 1252198800
          tz.transition 2010, 4, :o5, 1270339200
          tz.transition 2010, 9, :o6, 1283648400
          tz.transition 2011, 4, :o5, 1301788800
          tz.transition 2011, 9, :o6, 1315098000
          tz.transition 2012, 4, :o5, 1333238400
          tz.transition 2012, 9, :o6, 1346547600
          tz.transition 2013, 4, :o5, 1365292800
          tz.transition 2013, 9, :o6, 1377997200
          tz.transition 2014, 4, :o5, 1396742400
          tz.transition 2014, 9, :o6, 1410051600
          tz.transition 2015, 4, :o5, 1428192000
          tz.transition 2015, 9, :o6, 1441501200
          tz.transition 2016, 4, :o5, 1459641600
          tz.transition 2016, 9, :o6, 1472950800
          tz.transition 2017, 4, :o5, 1491091200
          tz.transition 2017, 9, :o6, 1504400400
          tz.transition 2018, 4, :o5, 1522540800
          tz.transition 2018, 9, :o6, 1535850000
          tz.transition 2019, 4, :o5, 1554595200
          tz.transition 2019, 9, :o6, 1567299600
          tz.transition 2020, 4, :o5, 1586044800
          tz.transition 2020, 9, :o6, 1599354000
          tz.transition 2021, 4, :o5, 1617494400
          tz.transition 2021, 9, :o6, 1630803600
          tz.transition 2022, 4, :o5, 1648944000
          tz.transition 2022, 9, :o6, 1662253200
          tz.transition 2023, 4, :o5, 1680393600
          tz.transition 2023, 9, :o6, 1693702800
          tz.transition 2024, 4, :o5, 1712448000
          tz.transition 2024, 9, :o6, 1725152400
          tz.transition 2025, 4, :o5, 1743897600
          tz.transition 2025, 9, :o6, 1757206800
          tz.transition 2026, 4, :o5, 1775347200
          tz.transition 2026, 9, :o6, 1788656400
          tz.transition 2027, 4, :o5, 1806796800
          tz.transition 2027, 9, :o6, 1820106000
          tz.transition 2028, 4, :o5, 1838246400
          tz.transition 2028, 9, :o6, 1851555600
          tz.transition 2029, 4, :o5, 1869696000
          tz.transition 2029, 9, :o6, 1883005200
          tz.transition 2030, 4, :o5, 1901750400
          tz.transition 2030, 9, :o6, 1914454800
          tz.transition 2031, 4, :o5, 1933200000
          tz.transition 2031, 9, :o6, 1946509200
          tz.transition 2032, 4, :o5, 1964649600
          tz.transition 2032, 9, :o6, 1977958800
          tz.transition 2033, 4, :o5, 1996099200
          tz.transition 2033, 9, :o6, 2009408400
          tz.transition 2034, 4, :o5, 2027548800
          tz.transition 2034, 9, :o6, 2040858000
          tz.transition 2035, 4, :o5, 2058998400
          tz.transition 2035, 9, :o6, 2072307600
          tz.transition 2036, 4, :o5, 2091052800
          tz.transition 2036, 9, :o6, 2104362000
          tz.transition 2037, 4, :o5, 2122502400
          tz.transition 2037, 9, :o6, 2135811600
          tz.transition 2038, 4, :o5, 4931035, 2
          tz.transition 2038, 9, :o6, 59176117, 24
          tz.transition 2039, 4, :o5, 4931763, 2
          tz.transition 2039, 9, :o6, 59184853, 24
          tz.transition 2040, 4, :o5, 4932491, 2
          tz.transition 2040, 9, :o6, 59193589, 24
          tz.transition 2041, 4, :o5, 4933233, 2
          tz.transition 2041, 9, :o6, 59202325, 24
          tz.transition 2042, 4, :o5, 4933961, 2
          tz.transition 2042, 9, :o6, 59211229, 24
          tz.transition 2043, 4, :o5, 4934689, 2
          tz.transition 2043, 9, :o6, 59219965, 24
          tz.transition 2044, 4, :o5, 4935417, 2
          tz.transition 2044, 9, :o6, 59228701, 24
          tz.transition 2045, 4, :o5, 4936145, 2
          tz.transition 2045, 9, :o6, 59237437, 24
          tz.transition 2046, 4, :o5, 4936873, 2
          tz.transition 2046, 9, :o6, 59246173, 24
          tz.transition 2047, 4, :o5, 4937615, 2
          tz.transition 2047, 9, :o6, 59254909, 24
          tz.transition 2048, 4, :o5, 4938343, 2
          tz.transition 2048, 9, :o6, 59263813, 24
          tz.transition 2049, 4, :o5, 4939071, 2
          tz.transition 2049, 9, :o6, 59272549, 24
          tz.transition 2050, 4, :o5, 4939799, 2
        end
      end
    end
  end
end
