module TZInfo
  module Definitions
    module Asia
      module Damascus
        include TimezoneDefinition
        
        timezone 'Asia/Damascus' do |tz|
          tz.offset :o0, 8712, 0, :LMT
          tz.offset :o1, 7200, 0, :EET
          tz.offset :o2, 7200, 3600, :EEST
          
          tz.transition 1919, 12, :o1, 2906789279, 1200
          tz.transition 1920, 4, :o2, 4844865, 2
          tz.transition 1920, 10, :o1, 58142411, 24
          tz.transition 1921, 4, :o2, 4845593, 2
          tz.transition 1921, 10, :o1, 58151147, 24
          tz.transition 1922, 4, :o2, 4846321, 2
          tz.transition 1922, 9, :o1, 58159883, 24
          tz.transition 1923, 4, :o2, 4847049, 2
          tz.transition 1923, 10, :o1, 58168787, 24
          tz.transition 1962, 4, :o2, 4875567, 2
          tz.transition 1962, 9, :o1, 58510523, 24
          tz.transition 1963, 5, :o2, 4876301, 2
          tz.transition 1963, 9, :o1, 58519259, 24
          tz.transition 1964, 5, :o2, 4877033, 2
          tz.transition 1964, 9, :o1, 58528067, 24
          tz.transition 1965, 5, :o2, 4877763, 2
          tz.transition 1965, 9, :o1, 58536803, 24
          tz.transition 1966, 4, :o2, 4878479, 2
          tz.transition 1966, 9, :o1, 58545587, 24
          tz.transition 1967, 5, :o2, 4879223, 2
          tz.transition 1967, 9, :o1, 58554347, 24
          tz.transition 1968, 5, :o2, 4879955, 2
          tz.transition 1968, 9, :o1, 58563131, 24
          tz.transition 1969, 5, :o2, 4880685, 2
          tz.transition 1969, 9, :o1, 58571891, 24
          tz.transition 1970, 5, :o2, 10368000
          tz.transition 1970, 9, :o1, 23583600
          tz.transition 1971, 5, :o2, 41904000
          tz.transition 1971, 9, :o1, 55119600
          tz.transition 1972, 5, :o2, 73526400
          tz.transition 1972, 9, :o1, 86742000
          tz.transition 1973, 5, :o2, 105062400
          tz.transition 1973, 9, :o1, 118278000
          tz.transition 1974, 5, :o2, 136598400
          tz.transition 1974, 9, :o1, 149814000
          tz.transition 1975, 5, :o2, 168134400
          tz.transition 1975, 9, :o1, 181350000
          tz.transition 1976, 5, :o2, 199756800
          tz.transition 1976, 9, :o1, 212972400
          tz.transition 1977, 5, :o2, 231292800
          tz.transition 1977, 8, :o1, 241916400
          tz.transition 1978, 5, :o2, 262828800
          tz.transition 1978, 8, :o1, 273452400
          tz.transition 1983, 4, :o2, 418694400
          tz.transition 1983, 9, :o1, 433810800
          tz.transition 1984, 4, :o2, 450316800
          tz.transition 1984, 9, :o1, 465433200
          tz.transition 1986, 2, :o2, 508896000
          tz.transition 1986, 10, :o1, 529196400
          tz.transition 1987, 3, :o2, 541555200
          tz.transition 1987, 10, :o1, 562633200
          tz.transition 1988, 3, :o2, 574387200
          tz.transition 1988, 10, :o1, 594255600
          tz.transition 1989, 3, :o2, 607305600
          tz.transition 1989, 9, :o1, 623199600
          tz.transition 1990, 4, :o2, 638928000
          tz.transition 1990, 9, :o1, 654649200
          tz.transition 1991, 3, :o2, 670456800
          tz.transition 1991, 9, :o1, 686264400
          tz.transition 1992, 4, :o2, 702684000
          tz.transition 1992, 9, :o1, 717886800
          tz.transition 1993, 3, :o2, 733096800
          tz.transition 1993, 9, :o1, 748904400
          tz.transition 1994, 3, :o2, 765151200
          tz.transition 1994, 9, :o1, 780958800
          tz.transition 1995, 3, :o2, 796687200
          tz.transition 1995, 9, :o1, 812494800
          tz.transition 1996, 3, :o2, 828309600
          tz.transition 1996, 9, :o1, 844117200
          tz.transition 1997, 3, :o2, 859759200
          tz.transition 1997, 9, :o1, 875653200
          tz.transition 1998, 3, :o2, 891208800
          tz.transition 1998, 9, :o1, 907189200
          tz.transition 1999, 3, :o2, 922917600
          tz.transition 1999, 9, :o1, 938725200
          tz.transition 2000, 3, :o2, 954540000
          tz.transition 2000, 9, :o1, 970347600
          tz.transition 2001, 3, :o2, 986076000
          tz.transition 2001, 9, :o1, 1001883600
          tz.transition 2002, 3, :o2, 1017612000
          tz.transition 2002, 9, :o1, 1033419600
          tz.transition 2003, 3, :o2, 1049148000
          tz.transition 2003, 9, :o1, 1064955600
          tz.transition 2004, 3, :o2, 1080770400
          tz.transition 2004, 9, :o1, 1096578000
          tz.transition 2005, 3, :o2, 1112306400
          tz.transition 2005, 9, :o1, 1128114000
          tz.transition 2006, 3, :o2, 1143842400
          tz.transition 2006, 9, :o1, 1158872400
          tz.transition 2007, 3, :o2, 1175205600
          tz.transition 2007, 11, :o1, 1193950800
          tz.transition 2008, 4, :o2, 1207260000
          tz.transition 2008, 10, :o1, 1225486800
          tz.transition 2009, 3, :o2, 1238104800
          tz.transition 2009, 10, :o1, 1256850000
          tz.transition 2010, 4, :o2, 1270159200
          tz.transition 2010, 10, :o1, 1288299600
          tz.transition 2011, 3, :o2, 1301608800
          tz.transition 2011, 10, :o1, 1319749200
          tz.transition 2012, 3, :o2, 1333058400
          tz.transition 2012, 10, :o1, 1351198800
          tz.transition 2013, 3, :o2, 1364508000
          tz.transition 2013, 10, :o1, 1382648400
          tz.transition 2014, 3, :o2, 1395957600
          tz.transition 2014, 10, :o1, 1414702800
          tz.transition 2015, 3, :o2, 1427407200
          tz.transition 2015, 10, :o1, 1446152400
          tz.transition 2016, 3, :o2, 1458856800
          tz.transition 2016, 10, :o1, 1477602000
          tz.transition 2017, 3, :o2, 1490911200
          tz.transition 2017, 10, :o1, 1509051600
          tz.transition 2018, 3, :o2, 1522360800
          tz.transition 2018, 10, :o1, 1540501200
          tz.transition 2019, 3, :o2, 1553810400
          tz.transition 2019, 10, :o1, 1571950800
          tz.transition 2020, 3, :o2, 1585260000
          tz.transition 2020, 10, :o1, 1604005200
          tz.transition 2021, 3, :o2, 1616709600
          tz.transition 2021, 10, :o1, 1635454800
          tz.transition 2022, 3, :o2, 1648159200
          tz.transition 2022, 10, :o1, 1666904400
          tz.transition 2023, 3, :o2, 1680213600
          tz.transition 2023, 10, :o1, 1698354000
          tz.transition 2024, 3, :o2, 1711663200
          tz.transition 2024, 10, :o1, 1729803600
          tz.transition 2025, 3, :o2, 1743112800
          tz.transition 2025, 10, :o1, 1761858000
          tz.transition 2026, 3, :o2, 1774562400
          tz.transition 2026, 10, :o1, 1793307600
          tz.transition 2027, 3, :o2, 1806012000
          tz.transition 2027, 10, :o1, 1824757200
          tz.transition 2028, 3, :o2, 1838066400
          tz.transition 2028, 10, :o1, 1856206800
          tz.transition 2029, 3, :o2, 1869516000
          tz.transition 2029, 10, :o1, 1887656400
          tz.transition 2030, 3, :o2, 1900965600
          tz.transition 2030, 10, :o1, 1919106000
          tz.transition 2031, 3, :o2, 1932415200
          tz.transition 2031, 10, :o1, 1951160400
          tz.transition 2032, 3, :o2, 1963864800
          tz.transition 2032, 10, :o1, 1982610000
          tz.transition 2033, 3, :o2, 1995314400
          tz.transition 2033, 10, :o1, 2014059600
          tz.transition 2034, 3, :o2, 2027368800
          tz.transition 2034, 10, :o1, 2045509200
          tz.transition 2035, 3, :o2, 2058818400
          tz.transition 2035, 10, :o1, 2076958800
          tz.transition 2036, 3, :o2, 2090268000
          tz.transition 2036, 10, :o1, 2109013200
          tz.transition 2037, 3, :o2, 2121717600
          tz.transition 2037, 10, :o1, 2140462800
          tz.transition 2038, 3, :o2, 29586101, 12
          tz.transition 2038, 10, :o1, 19725803, 8
          tz.transition 2039, 3, :o2, 29590469, 12
          tz.transition 2039, 10, :o1, 19728715, 8
          tz.transition 2040, 3, :o2, 29594921, 12
          tz.transition 2040, 10, :o1, 19731627, 8
          tz.transition 2041, 3, :o2, 29599289, 12
          tz.transition 2041, 10, :o1, 19734539, 8
          tz.transition 2042, 3, :o2, 29603657, 12
          tz.transition 2042, 10, :o1, 19737507, 8
          tz.transition 2043, 3, :o2, 29608025, 12
          tz.transition 2043, 10, :o1, 19740419, 8
          tz.transition 2044, 3, :o2, 29612393, 12
          tz.transition 2044, 10, :o1, 19743331, 8
          tz.transition 2045, 3, :o2, 29616845, 12
          tz.transition 2045, 10, :o1, 19746243, 8
          tz.transition 2046, 3, :o2, 29621213, 12
          tz.transition 2046, 10, :o1, 19749155, 8
          tz.transition 2047, 3, :o2, 29625581, 12
          tz.transition 2047, 10, :o1, 19752067, 8
          tz.transition 2048, 3, :o2, 29629949, 12
          tz.transition 2048, 10, :o1, 19755035, 8
          tz.transition 2049, 3, :o2, 29634317, 12
          tz.transition 2049, 10, :o1, 19757947, 8
          tz.transition 2050, 3, :o2, 29638685, 12
          tz.transition 2050, 10, :o1, 19760859, 8
        end
      end
    end
  end
end
