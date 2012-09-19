module TZInfo
  module Definitions
    module Australia
      module Lord_Howe
        include TimezoneDefinition
        
        timezone 'Australia/Lord_Howe' do |tz|
          tz.offset :o0, 38180, 0, :LMT
          tz.offset :o1, 36000, 0, :EST
          tz.offset :o2, 37800, 0, :LHST
          tz.offset :o3, 37800, 3600, :LHST
          tz.offset :o4, 37800, 1800, :LHST
          
          tz.transition 1895, 1, :o1, 10425132251, 4320
          tz.transition 1981, 2, :o2, 352216800
          tz.transition 1981, 10, :o3, 372785400
          tz.transition 1982, 3, :o2, 384273000
          tz.transition 1982, 10, :o3, 404839800
          tz.transition 1983, 3, :o2, 415722600
          tz.transition 1983, 10, :o3, 436289400
          tz.transition 1984, 3, :o2, 447172200
          tz.transition 1984, 10, :o3, 467739000
          tz.transition 1985, 3, :o2, 478621800
          tz.transition 1985, 10, :o4, 499188600
          tz.transition 1986, 3, :o2, 511282800
          tz.transition 1986, 10, :o4, 530033400
          tz.transition 1987, 3, :o2, 542732400
          tz.transition 1987, 10, :o4, 562087800
          tz.transition 1988, 3, :o2, 574786800
          tz.transition 1988, 10, :o4, 594142200
          tz.transition 1989, 3, :o2, 606236400
          tz.transition 1989, 10, :o4, 625591800
          tz.transition 1990, 3, :o2, 636476400
          tz.transition 1990, 10, :o4, 657041400
          tz.transition 1991, 3, :o2, 667926000
          tz.transition 1991, 10, :o4, 688491000
          tz.transition 1992, 2, :o2, 699375600
          tz.transition 1992, 10, :o4, 719940600
          tz.transition 1993, 3, :o2, 731430000
          tz.transition 1993, 10, :o4, 751995000
          tz.transition 1994, 3, :o2, 762879600
          tz.transition 1994, 10, :o4, 783444600
          tz.transition 1995, 3, :o2, 794329200
          tz.transition 1995, 10, :o4, 814894200
          tz.transition 1996, 3, :o2, 828198000
          tz.transition 1996, 10, :o4, 846343800
          tz.transition 1997, 3, :o2, 859647600
          tz.transition 1997, 10, :o4, 877793400
          tz.transition 1998, 3, :o2, 891097200
          tz.transition 1998, 10, :o4, 909243000
          tz.transition 1999, 3, :o2, 922546800
          tz.transition 1999, 10, :o4, 941297400
          tz.transition 2000, 3, :o2, 953996400
          tz.transition 2000, 8, :o4, 967303800
          tz.transition 2001, 3, :o2, 985446000
          tz.transition 2001, 10, :o4, 1004196600
          tz.transition 2002, 3, :o2, 1017500400
          tz.transition 2002, 10, :o4, 1035646200
          tz.transition 2003, 3, :o2, 1048950000
          tz.transition 2003, 10, :o4, 1067095800
          tz.transition 2004, 3, :o2, 1080399600
          tz.transition 2004, 10, :o4, 1099150200
          tz.transition 2005, 3, :o2, 1111849200
          tz.transition 2005, 10, :o4, 1130599800
          tz.transition 2006, 4, :o2, 1143903600
          tz.transition 2006, 10, :o4, 1162049400
          tz.transition 2007, 3, :o2, 1174748400
          tz.transition 2007, 10, :o4, 1193499000
          tz.transition 2008, 4, :o2, 1207407600
          tz.transition 2008, 10, :o4, 1223134200
          tz.transition 2009, 4, :o2, 1238857200
          tz.transition 2009, 10, :o4, 1254583800
          tz.transition 2010, 4, :o2, 1270306800
          tz.transition 2010, 10, :o4, 1286033400
          tz.transition 2011, 4, :o2, 1301756400
          tz.transition 2011, 10, :o4, 1317483000
          tz.transition 2012, 3, :o2, 1333206000
          tz.transition 2012, 10, :o4, 1349537400
          tz.transition 2013, 4, :o2, 1365260400
          tz.transition 2013, 10, :o4, 1380987000
          tz.transition 2014, 4, :o2, 1396710000
          tz.transition 2014, 10, :o4, 1412436600
          tz.transition 2015, 4, :o2, 1428159600
          tz.transition 2015, 10, :o4, 1443886200
          tz.transition 2016, 4, :o2, 1459609200
          tz.transition 2016, 10, :o4, 1475335800
          tz.transition 2017, 4, :o2, 1491058800
          tz.transition 2017, 9, :o4, 1506785400
          tz.transition 2018, 3, :o2, 1522508400
          tz.transition 2018, 10, :o4, 1538839800
          tz.transition 2019, 4, :o2, 1554562800
          tz.transition 2019, 10, :o4, 1570289400
          tz.transition 2020, 4, :o2, 1586012400
          tz.transition 2020, 10, :o4, 1601739000
          tz.transition 2021, 4, :o2, 1617462000
          tz.transition 2021, 10, :o4, 1633188600
          tz.transition 2022, 4, :o2, 1648911600
          tz.transition 2022, 10, :o4, 1664638200
          tz.transition 2023, 4, :o2, 1680361200
          tz.transition 2023, 9, :o4, 1696087800
          tz.transition 2024, 4, :o2, 1712415600
          tz.transition 2024, 10, :o4, 1728142200
          tz.transition 2025, 4, :o2, 1743865200
          tz.transition 2025, 10, :o4, 1759591800
          tz.transition 2026, 4, :o2, 1775314800
          tz.transition 2026, 10, :o4, 1791041400
          tz.transition 2027, 4, :o2, 1806764400
          tz.transition 2027, 10, :o4, 1822491000
          tz.transition 2028, 4, :o2, 1838214000
          tz.transition 2028, 9, :o4, 1853940600
          tz.transition 2029, 3, :o2, 1869663600
          tz.transition 2029, 10, :o4, 1885995000
          tz.transition 2030, 4, :o2, 1901718000
          tz.transition 2030, 10, :o4, 1917444600
          tz.transition 2031, 4, :o2, 1933167600
          tz.transition 2031, 10, :o4, 1948894200
          tz.transition 2032, 4, :o2, 1964617200
          tz.transition 2032, 10, :o4, 1980343800
          tz.transition 2033, 4, :o2, 1996066800
          tz.transition 2033, 10, :o4, 2011793400
          tz.transition 2034, 4, :o2, 2027516400
          tz.transition 2034, 9, :o4, 2043243000
          tz.transition 2035, 3, :o2, 2058966000
          tz.transition 2035, 10, :o4, 2075297400
          tz.transition 2036, 4, :o2, 2091020400
          tz.transition 2036, 10, :o4, 2106747000
          tz.transition 2037, 4, :o2, 2122470000
          tz.transition 2037, 10, :o4, 2138196600
          tz.transition 2038, 4, :o2, 19724137, 8
          tz.transition 2038, 10, :o4, 118353559, 48
          tz.transition 2039, 4, :o2, 19727049, 8
          tz.transition 2039, 10, :o4, 118371031, 48
          tz.transition 2040, 3, :o2, 19729961, 8
          tz.transition 2040, 10, :o4, 118388839, 48
          tz.transition 2041, 4, :o2, 19732929, 8
          tz.transition 2041, 10, :o4, 118406311, 48
          tz.transition 2042, 4, :o2, 19735841, 8
          tz.transition 2042, 10, :o4, 118423783, 48
          tz.transition 2043, 4, :o2, 19738753, 8
          tz.transition 2043, 10, :o4, 118441255, 48
          tz.transition 2044, 4, :o2, 19741665, 8
          tz.transition 2044, 10, :o4, 118458727, 48
          tz.transition 2045, 4, :o2, 19744577, 8
          tz.transition 2045, 9, :o4, 118476199, 48
          tz.transition 2046, 3, :o2, 19747489, 8
          tz.transition 2046, 10, :o4, 118494007, 48
          tz.transition 2047, 4, :o2, 19750457, 8
          tz.transition 2047, 10, :o4, 118511479, 48
          tz.transition 2048, 4, :o2, 19753369, 8
          tz.transition 2048, 10, :o4, 118528951, 48
          tz.transition 2049, 4, :o2, 19756281, 8
          tz.transition 2049, 10, :o4, 118546423, 48
          tz.transition 2050, 4, :o2, 19759193, 8
        end
      end
    end
  end
end
