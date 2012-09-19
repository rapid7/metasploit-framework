module TZInfo
  module Definitions
    module Europe
      module Gibraltar
        include TimezoneDefinition
        
        timezone 'Europe/Gibraltar' do |tz|
          tz.offset :o0, -1284, 0, :LMT
          tz.offset :o1, 0, 0, :GMT
          tz.offset :o2, 0, 3600, :BST
          tz.offset :o3, 0, 7200, :BDST
          tz.offset :o4, 3600, 0, :CET
          tz.offset :o5, 3600, 3600, :CEST
          
          tz.transition 1880, 8, :o1, 17337092507, 7200
          tz.transition 1916, 5, :o2, 29052055, 12
          tz.transition 1916, 10, :o1, 29053651, 12
          tz.transition 1917, 4, :o2, 29055919, 12
          tz.transition 1917, 9, :o1, 29057863, 12
          tz.transition 1918, 3, :o2, 29060119, 12
          tz.transition 1918, 9, :o1, 29062399, 12
          tz.transition 1919, 3, :o2, 29064571, 12
          tz.transition 1919, 9, :o1, 29066767, 12
          tz.transition 1920, 3, :o2, 29068939, 12
          tz.transition 1920, 10, :o1, 29071471, 12
          tz.transition 1921, 4, :o2, 29073391, 12
          tz.transition 1921, 10, :o1, 29075587, 12
          tz.transition 1922, 3, :o2, 29077675, 12
          tz.transition 1922, 10, :o1, 29080027, 12
          tz.transition 1923, 4, :o2, 29082379, 12
          tz.transition 1923, 9, :o1, 29084143, 12
          tz.transition 1924, 4, :o2, 29086663, 12
          tz.transition 1924, 9, :o1, 29088595, 12
          tz.transition 1925, 4, :o2, 29091115, 12
          tz.transition 1925, 10, :o1, 29093131, 12
          tz.transition 1926, 4, :o2, 29095483, 12
          tz.transition 1926, 10, :o1, 29097499, 12
          tz.transition 1927, 4, :o2, 29099767, 12
          tz.transition 1927, 10, :o1, 29101867, 12
          tz.transition 1928, 4, :o2, 29104303, 12
          tz.transition 1928, 10, :o1, 29106319, 12
          tz.transition 1929, 4, :o2, 29108671, 12
          tz.transition 1929, 10, :o1, 29110687, 12
          tz.transition 1930, 4, :o2, 29112955, 12
          tz.transition 1930, 10, :o1, 29115055, 12
          tz.transition 1931, 4, :o2, 29117407, 12
          tz.transition 1931, 10, :o1, 29119423, 12
          tz.transition 1932, 4, :o2, 29121775, 12
          tz.transition 1932, 10, :o1, 29123791, 12
          tz.transition 1933, 4, :o2, 29126059, 12
          tz.transition 1933, 10, :o1, 29128243, 12
          tz.transition 1934, 4, :o2, 29130595, 12
          tz.transition 1934, 10, :o1, 29132611, 12
          tz.transition 1935, 4, :o2, 29134879, 12
          tz.transition 1935, 10, :o1, 29136979, 12
          tz.transition 1936, 4, :o2, 29139331, 12
          tz.transition 1936, 10, :o1, 29141347, 12
          tz.transition 1937, 4, :o2, 29143699, 12
          tz.transition 1937, 10, :o1, 29145715, 12
          tz.transition 1938, 4, :o2, 29147983, 12
          tz.transition 1938, 10, :o1, 29150083, 12
          tz.transition 1939, 4, :o2, 29152435, 12
          tz.transition 1939, 11, :o1, 29155039, 12
          tz.transition 1940, 2, :o2, 29156215, 12
          tz.transition 1941, 5, :o3, 58322845, 24
          tz.transition 1941, 8, :o2, 58325197, 24
          tz.transition 1942, 4, :o3, 58330909, 24
          tz.transition 1942, 8, :o2, 58333933, 24
          tz.transition 1943, 4, :o3, 58339645, 24
          tz.transition 1943, 8, :o2, 58342837, 24
          tz.transition 1944, 4, :o3, 58348381, 24
          tz.transition 1944, 9, :o2, 58352413, 24
          tz.transition 1945, 4, :o3, 58357141, 24
          tz.transition 1945, 7, :o2, 58359637, 24
          tz.transition 1945, 10, :o1, 29180827, 12
          tz.transition 1946, 4, :o2, 29183095, 12
          tz.transition 1946, 10, :o1, 29185195, 12
          tz.transition 1947, 3, :o2, 29187127, 12
          tz.transition 1947, 4, :o3, 58374925, 24
          tz.transition 1947, 8, :o2, 58377781, 24
          tz.transition 1947, 11, :o1, 29189899, 12
          tz.transition 1948, 3, :o2, 29191495, 12
          tz.transition 1948, 10, :o1, 29194267, 12
          tz.transition 1949, 4, :o2, 29196115, 12
          tz.transition 1949, 10, :o1, 29198635, 12
          tz.transition 1950, 4, :o2, 29200651, 12
          tz.transition 1950, 10, :o1, 29202919, 12
          tz.transition 1951, 4, :o2, 29205019, 12
          tz.transition 1951, 10, :o1, 29207287, 12
          tz.transition 1952, 4, :o2, 29209471, 12
          tz.transition 1952, 10, :o1, 29211739, 12
          tz.transition 1953, 4, :o2, 29213839, 12
          tz.transition 1953, 10, :o1, 29215855, 12
          tz.transition 1954, 4, :o2, 29218123, 12
          tz.transition 1954, 10, :o1, 29220223, 12
          tz.transition 1955, 4, :o2, 29222575, 12
          tz.transition 1955, 10, :o1, 29224591, 12
          tz.transition 1956, 4, :o2, 29227027, 12
          tz.transition 1956, 10, :o1, 29229043, 12
          tz.transition 1957, 4, :o4, 29231311, 12
          tz.transition 1982, 3, :o5, 386125200
          tz.transition 1982, 9, :o4, 401850000
          tz.transition 1983, 3, :o5, 417574800
          tz.transition 1983, 9, :o4, 433299600
          tz.transition 1984, 3, :o5, 449024400
          tz.transition 1984, 9, :o4, 465354000
          tz.transition 1985, 3, :o5, 481078800
          tz.transition 1985, 9, :o4, 496803600
          tz.transition 1986, 3, :o5, 512528400
          tz.transition 1986, 9, :o4, 528253200
          tz.transition 1987, 3, :o5, 543978000
          tz.transition 1987, 9, :o4, 559702800
          tz.transition 1988, 3, :o5, 575427600
          tz.transition 1988, 9, :o4, 591152400
          tz.transition 1989, 3, :o5, 606877200
          tz.transition 1989, 9, :o4, 622602000
          tz.transition 1990, 3, :o5, 638326800
          tz.transition 1990, 9, :o4, 654656400
          tz.transition 1991, 3, :o5, 670381200
          tz.transition 1991, 9, :o4, 686106000
          tz.transition 1992, 3, :o5, 701830800
          tz.transition 1992, 9, :o4, 717555600
          tz.transition 1993, 3, :o5, 733280400
          tz.transition 1993, 9, :o4, 749005200
          tz.transition 1994, 3, :o5, 764730000
          tz.transition 1994, 9, :o4, 780454800
          tz.transition 1995, 3, :o5, 796179600
          tz.transition 1995, 9, :o4, 811904400
          tz.transition 1996, 3, :o5, 828234000
          tz.transition 1996, 10, :o4, 846378000
          tz.transition 1997, 3, :o5, 859683600
          tz.transition 1997, 10, :o4, 877827600
          tz.transition 1998, 3, :o5, 891133200
          tz.transition 1998, 10, :o4, 909277200
          tz.transition 1999, 3, :o5, 922582800
          tz.transition 1999, 10, :o4, 941331600
          tz.transition 2000, 3, :o5, 954032400
          tz.transition 2000, 10, :o4, 972781200
          tz.transition 2001, 3, :o5, 985482000
          tz.transition 2001, 10, :o4, 1004230800
          tz.transition 2002, 3, :o5, 1017536400
          tz.transition 2002, 10, :o4, 1035680400
          tz.transition 2003, 3, :o5, 1048986000
          tz.transition 2003, 10, :o4, 1067130000
          tz.transition 2004, 3, :o5, 1080435600
          tz.transition 2004, 10, :o4, 1099184400
          tz.transition 2005, 3, :o5, 1111885200
          tz.transition 2005, 10, :o4, 1130634000
          tz.transition 2006, 3, :o5, 1143334800
          tz.transition 2006, 10, :o4, 1162083600
          tz.transition 2007, 3, :o5, 1174784400
          tz.transition 2007, 10, :o4, 1193533200
          tz.transition 2008, 3, :o5, 1206838800
          tz.transition 2008, 10, :o4, 1224982800
          tz.transition 2009, 3, :o5, 1238288400
          tz.transition 2009, 10, :o4, 1256432400
          tz.transition 2010, 3, :o5, 1269738000
          tz.transition 2010, 10, :o4, 1288486800
          tz.transition 2011, 3, :o5, 1301187600
          tz.transition 2011, 10, :o4, 1319936400
          tz.transition 2012, 3, :o5, 1332637200
          tz.transition 2012, 10, :o4, 1351386000
          tz.transition 2013, 3, :o5, 1364691600
          tz.transition 2013, 10, :o4, 1382835600
          tz.transition 2014, 3, :o5, 1396141200
          tz.transition 2014, 10, :o4, 1414285200
          tz.transition 2015, 3, :o5, 1427590800
          tz.transition 2015, 10, :o4, 1445734800
          tz.transition 2016, 3, :o5, 1459040400
          tz.transition 2016, 10, :o4, 1477789200
          tz.transition 2017, 3, :o5, 1490490000
          tz.transition 2017, 10, :o4, 1509238800
          tz.transition 2018, 3, :o5, 1521939600
          tz.transition 2018, 10, :o4, 1540688400
          tz.transition 2019, 3, :o5, 1553994000
          tz.transition 2019, 10, :o4, 1572138000
          tz.transition 2020, 3, :o5, 1585443600
          tz.transition 2020, 10, :o4, 1603587600
          tz.transition 2021, 3, :o5, 1616893200
          tz.transition 2021, 10, :o4, 1635642000
          tz.transition 2022, 3, :o5, 1648342800
          tz.transition 2022, 10, :o4, 1667091600
          tz.transition 2023, 3, :o5, 1679792400
          tz.transition 2023, 10, :o4, 1698541200
          tz.transition 2024, 3, :o5, 1711846800
          tz.transition 2024, 10, :o4, 1729990800
          tz.transition 2025, 3, :o5, 1743296400
          tz.transition 2025, 10, :o4, 1761440400
          tz.transition 2026, 3, :o5, 1774746000
          tz.transition 2026, 10, :o4, 1792890000
          tz.transition 2027, 3, :o5, 1806195600
          tz.transition 2027, 10, :o4, 1824944400
          tz.transition 2028, 3, :o5, 1837645200
          tz.transition 2028, 10, :o4, 1856394000
          tz.transition 2029, 3, :o5, 1869094800
          tz.transition 2029, 10, :o4, 1887843600
          tz.transition 2030, 3, :o5, 1901149200
          tz.transition 2030, 10, :o4, 1919293200
          tz.transition 2031, 3, :o5, 1932598800
          tz.transition 2031, 10, :o4, 1950742800
          tz.transition 2032, 3, :o5, 1964048400
          tz.transition 2032, 10, :o4, 1982797200
          tz.transition 2033, 3, :o5, 1995498000
          tz.transition 2033, 10, :o4, 2014246800
          tz.transition 2034, 3, :o5, 2026947600
          tz.transition 2034, 10, :o4, 2045696400
          tz.transition 2035, 3, :o5, 2058397200
          tz.transition 2035, 10, :o4, 2077146000
          tz.transition 2036, 3, :o5, 2090451600
          tz.transition 2036, 10, :o4, 2108595600
          tz.transition 2037, 3, :o5, 2121901200
          tz.transition 2037, 10, :o4, 2140045200
          tz.transition 2038, 3, :o5, 59172253, 24
          tz.transition 2038, 10, :o4, 59177461, 24
          tz.transition 2039, 3, :o5, 59180989, 24
          tz.transition 2039, 10, :o4, 59186197, 24
          tz.transition 2040, 3, :o5, 59189725, 24
          tz.transition 2040, 10, :o4, 59194933, 24
          tz.transition 2041, 3, :o5, 59198629, 24
          tz.transition 2041, 10, :o4, 59203669, 24
          tz.transition 2042, 3, :o5, 59207365, 24
          tz.transition 2042, 10, :o4, 59212405, 24
          tz.transition 2043, 3, :o5, 59216101, 24
          tz.transition 2043, 10, :o4, 59221141, 24
          tz.transition 2044, 3, :o5, 59224837, 24
          tz.transition 2044, 10, :o4, 59230045, 24
          tz.transition 2045, 3, :o5, 59233573, 24
          tz.transition 2045, 10, :o4, 59238781, 24
          tz.transition 2046, 3, :o5, 59242309, 24
          tz.transition 2046, 10, :o4, 59247517, 24
          tz.transition 2047, 3, :o5, 59251213, 24
          tz.transition 2047, 10, :o4, 59256253, 24
          tz.transition 2048, 3, :o5, 59259949, 24
          tz.transition 2048, 10, :o4, 59264989, 24
          tz.transition 2049, 3, :o5, 59268685, 24
          tz.transition 2049, 10, :o4, 59273893, 24
          tz.transition 2050, 3, :o5, 59277421, 24
          tz.transition 2050, 10, :o4, 59282629, 24
        end
      end
    end
  end
end
