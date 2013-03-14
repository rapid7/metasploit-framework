module TZInfo
  module Definitions
    module America
      module Whitehorse
        include TimezoneDefinition
        
        timezone 'America/Whitehorse' do |tz|
          tz.offset :o0, -32412, 0, :LMT
          tz.offset :o1, -32400, 0, :YST
          tz.offset :o2, -32400, 3600, :YDT
          tz.offset :o3, -32400, 3600, :YWT
          tz.offset :o4, -32400, 3600, :YPT
          tz.offset :o5, -32400, 7200, :YDDT
          tz.offset :o6, -28800, 0, :PST
          tz.offset :o7, -28800, 3600, :PDT
          
          tz.transition 1900, 8, :o1, 17389813501, 7200
          tz.transition 1918, 4, :o2, 58120751, 24
          tz.transition 1918, 10, :o1, 29062727, 12
          tz.transition 1919, 5, :o2, 58130495, 24
          tz.transition 1919, 11, :o1, 14533583, 6
          tz.transition 1942, 2, :o3, 58329599, 24
          tz.transition 1945, 8, :o4, 58360379, 24
          tz.transition 1945, 9, :o1, 29180747, 12
          tz.transition 1965, 4, :o5, 19511007, 8
          tz.transition 1965, 10, :o1, 19512519, 8
          tz.transition 1966, 7, :o6, 58543391, 24
          tz.transition 1980, 4, :o7, 325677600
          tz.transition 1980, 10, :o6, 341398800
          tz.transition 1981, 4, :o7, 357127200
          tz.transition 1981, 10, :o6, 372848400
          tz.transition 1982, 4, :o7, 388576800
          tz.transition 1982, 10, :o6, 404902800
          tz.transition 1983, 4, :o7, 420026400
          tz.transition 1983, 10, :o6, 436352400
          tz.transition 1984, 4, :o7, 452080800
          tz.transition 1984, 10, :o6, 467802000
          tz.transition 1985, 4, :o7, 483530400
          tz.transition 1985, 10, :o6, 499251600
          tz.transition 1986, 4, :o7, 514980000
          tz.transition 1986, 10, :o6, 530701200
          tz.transition 1987, 4, :o7, 544615200
          tz.transition 1987, 10, :o6, 562150800
          tz.transition 1988, 4, :o7, 576064800
          tz.transition 1988, 10, :o6, 594205200
          tz.transition 1989, 4, :o7, 607514400
          tz.transition 1989, 10, :o6, 625654800
          tz.transition 1990, 4, :o7, 638964000
          tz.transition 1990, 10, :o6, 657104400
          tz.transition 1991, 4, :o7, 671018400
          tz.transition 1991, 10, :o6, 688554000
          tz.transition 1992, 4, :o7, 702468000
          tz.transition 1992, 10, :o6, 720003600
          tz.transition 1993, 4, :o7, 733917600
          tz.transition 1993, 10, :o6, 752058000
          tz.transition 1994, 4, :o7, 765367200
          tz.transition 1994, 10, :o6, 783507600
          tz.transition 1995, 4, :o7, 796816800
          tz.transition 1995, 10, :o6, 814957200
          tz.transition 1996, 4, :o7, 828871200
          tz.transition 1996, 10, :o6, 846406800
          tz.transition 1997, 4, :o7, 860320800
          tz.transition 1997, 10, :o6, 877856400
          tz.transition 1998, 4, :o7, 891770400
          tz.transition 1998, 10, :o6, 909306000
          tz.transition 1999, 4, :o7, 923220000
          tz.transition 1999, 10, :o6, 941360400
          tz.transition 2000, 4, :o7, 954669600
          tz.transition 2000, 10, :o6, 972810000
          tz.transition 2001, 4, :o7, 986119200
          tz.transition 2001, 10, :o6, 1004259600
          tz.transition 2002, 4, :o7, 1018173600
          tz.transition 2002, 10, :o6, 1035709200
          tz.transition 2003, 4, :o7, 1049623200
          tz.transition 2003, 10, :o6, 1067158800
          tz.transition 2004, 4, :o7, 1081072800
          tz.transition 2004, 10, :o6, 1099213200
          tz.transition 2005, 4, :o7, 1112522400
          tz.transition 2005, 10, :o6, 1130662800
          tz.transition 2006, 4, :o7, 1143972000
          tz.transition 2006, 10, :o6, 1162112400
          tz.transition 2007, 3, :o7, 1173607200
          tz.transition 2007, 11, :o6, 1194166800
          tz.transition 2008, 3, :o7, 1205056800
          tz.transition 2008, 11, :o6, 1225616400
          tz.transition 2009, 3, :o7, 1236506400
          tz.transition 2009, 11, :o6, 1257066000
          tz.transition 2010, 3, :o7, 1268560800
          tz.transition 2010, 11, :o6, 1289120400
          tz.transition 2011, 3, :o7, 1300010400
          tz.transition 2011, 11, :o6, 1320570000
          tz.transition 2012, 3, :o7, 1331460000
          tz.transition 2012, 11, :o6, 1352019600
          tz.transition 2013, 3, :o7, 1362909600
          tz.transition 2013, 11, :o6, 1383469200
          tz.transition 2014, 3, :o7, 1394359200
          tz.transition 2014, 11, :o6, 1414918800
          tz.transition 2015, 3, :o7, 1425808800
          tz.transition 2015, 11, :o6, 1446368400
          tz.transition 2016, 3, :o7, 1457863200
          tz.transition 2016, 11, :o6, 1478422800
          tz.transition 2017, 3, :o7, 1489312800
          tz.transition 2017, 11, :o6, 1509872400
          tz.transition 2018, 3, :o7, 1520762400
          tz.transition 2018, 11, :o6, 1541322000
          tz.transition 2019, 3, :o7, 1552212000
          tz.transition 2019, 11, :o6, 1572771600
          tz.transition 2020, 3, :o7, 1583661600
          tz.transition 2020, 11, :o6, 1604221200
          tz.transition 2021, 3, :o7, 1615716000
          tz.transition 2021, 11, :o6, 1636275600
          tz.transition 2022, 3, :o7, 1647165600
          tz.transition 2022, 11, :o6, 1667725200
          tz.transition 2023, 3, :o7, 1678615200
          tz.transition 2023, 11, :o6, 1699174800
          tz.transition 2024, 3, :o7, 1710064800
          tz.transition 2024, 11, :o6, 1730624400
          tz.transition 2025, 3, :o7, 1741514400
          tz.transition 2025, 11, :o6, 1762074000
          tz.transition 2026, 3, :o7, 1772964000
          tz.transition 2026, 11, :o6, 1793523600
          tz.transition 2027, 3, :o7, 1805018400
          tz.transition 2027, 11, :o6, 1825578000
          tz.transition 2028, 3, :o7, 1836468000
          tz.transition 2028, 11, :o6, 1857027600
          tz.transition 2029, 3, :o7, 1867917600
          tz.transition 2029, 11, :o6, 1888477200
          tz.transition 2030, 3, :o7, 1899367200
          tz.transition 2030, 11, :o6, 1919926800
          tz.transition 2031, 3, :o7, 1930816800
          tz.transition 2031, 11, :o6, 1951376400
          tz.transition 2032, 3, :o7, 1962871200
          tz.transition 2032, 11, :o6, 1983430800
          tz.transition 2033, 3, :o7, 1994320800
          tz.transition 2033, 11, :o6, 2014880400
          tz.transition 2034, 3, :o7, 2025770400
          tz.transition 2034, 11, :o6, 2046330000
          tz.transition 2035, 3, :o7, 2057220000
          tz.transition 2035, 11, :o6, 2077779600
          tz.transition 2036, 3, :o7, 2088669600
          tz.transition 2036, 11, :o6, 2109229200
          tz.transition 2037, 3, :o7, 2120119200
          tz.transition 2037, 11, :o6, 2140678800
          tz.transition 2038, 3, :o7, 29585963, 12
          tz.transition 2038, 11, :o6, 19725879, 8
          tz.transition 2039, 3, :o7, 29590331, 12
          tz.transition 2039, 11, :o6, 19728791, 8
          tz.transition 2040, 3, :o7, 29594699, 12
          tz.transition 2040, 11, :o6, 19731703, 8
          tz.transition 2041, 3, :o7, 29599067, 12
          tz.transition 2041, 11, :o6, 19734615, 8
          tz.transition 2042, 3, :o7, 29603435, 12
          tz.transition 2042, 11, :o6, 19737527, 8
          tz.transition 2043, 3, :o7, 29607803, 12
          tz.transition 2043, 11, :o6, 19740439, 8
          tz.transition 2044, 3, :o7, 29612255, 12
          tz.transition 2044, 11, :o6, 19743407, 8
          tz.transition 2045, 3, :o7, 29616623, 12
          tz.transition 2045, 11, :o6, 19746319, 8
          tz.transition 2046, 3, :o7, 29620991, 12
          tz.transition 2046, 11, :o6, 19749231, 8
          tz.transition 2047, 3, :o7, 29625359, 12
          tz.transition 2047, 11, :o6, 19752143, 8
          tz.transition 2048, 3, :o7, 29629727, 12
          tz.transition 2048, 11, :o6, 19755055, 8
          tz.transition 2049, 3, :o7, 29634179, 12
          tz.transition 2049, 11, :o6, 19758023, 8
          tz.transition 2050, 3, :o7, 29638547, 12
          tz.transition 2050, 11, :o6, 19760935, 8
        end
      end
    end
  end
end
