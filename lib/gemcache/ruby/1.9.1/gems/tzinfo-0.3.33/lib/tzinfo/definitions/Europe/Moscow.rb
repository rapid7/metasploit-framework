module TZInfo
  module Definitions
    module Europe
      module Moscow
        include TimezoneDefinition
        
        timezone 'Europe/Moscow' do |tz|
          tz.offset :o0, 9020, 0, :LMT
          tz.offset :o1, 9000, 0, :MMT
          tz.offset :o2, 9048, 0, :MMT
          tz.offset :o3, 9048, 3600, :MST
          tz.offset :o4, 9048, 7200, :MDST
          tz.offset :o5, 10800, 3600, :MSD
          tz.offset :o6, 10800, 0, :MSK
          tz.offset :o7, 10800, 7200, :MSD
          tz.offset :o8, 7200, 0, :EET
          tz.offset :o9, 7200, 3600, :EEST
          tz.offset :o10, 14400, 0, :MSK
          
          tz.transition 1879, 12, :o1, 10401330509, 4320
          tz.transition 1916, 7, :o2, 116210275, 48
          tz.transition 1917, 7, :o3, 8717080873, 3600
          tz.transition 1917, 12, :o2, 8717725273, 3600
          tz.transition 1918, 5, :o4, 8718283123, 3600
          tz.transition 1918, 9, :o3, 8718668473, 3600
          tz.transition 1919, 5, :o4, 8719597123, 3600
          tz.transition 1919, 6, :o5, 8719705423, 3600
          tz.transition 1919, 8, :o6, 7266559, 3
          tz.transition 1921, 2, :o5, 7268206, 3
          tz.transition 1921, 3, :o7, 58146463, 24
          tz.transition 1921, 8, :o5, 58150399, 24
          tz.transition 1921, 9, :o6, 7268890, 3
          tz.transition 1922, 9, :o8, 19386627, 8
          tz.transition 1930, 6, :o6, 29113781, 12
          tz.transition 1981, 3, :o5, 354920400
          tz.transition 1981, 9, :o6, 370728000
          tz.transition 1982, 3, :o5, 386456400
          tz.transition 1982, 9, :o6, 402264000
          tz.transition 1983, 3, :o5, 417992400
          tz.transition 1983, 9, :o6, 433800000
          tz.transition 1984, 3, :o5, 449614800
          tz.transition 1984, 9, :o6, 465346800
          tz.transition 1985, 3, :o5, 481071600
          tz.transition 1985, 9, :o6, 496796400
          tz.transition 1986, 3, :o5, 512521200
          tz.transition 1986, 9, :o6, 528246000
          tz.transition 1987, 3, :o5, 543970800
          tz.transition 1987, 9, :o6, 559695600
          tz.transition 1988, 3, :o5, 575420400
          tz.transition 1988, 9, :o6, 591145200
          tz.transition 1989, 3, :o5, 606870000
          tz.transition 1989, 9, :o6, 622594800
          tz.transition 1990, 3, :o5, 638319600
          tz.transition 1990, 9, :o6, 654649200
          tz.transition 1991, 3, :o9, 670374000
          tz.transition 1991, 9, :o8, 686102400
          tz.transition 1992, 1, :o6, 695779200
          tz.transition 1992, 3, :o5, 701812800
          tz.transition 1992, 9, :o6, 717534000
          tz.transition 1993, 3, :o5, 733273200
          tz.transition 1993, 9, :o6, 748998000
          tz.transition 1994, 3, :o5, 764722800
          tz.transition 1994, 9, :o6, 780447600
          tz.transition 1995, 3, :o5, 796172400
          tz.transition 1995, 9, :o6, 811897200
          tz.transition 1996, 3, :o5, 828226800
          tz.transition 1996, 10, :o6, 846370800
          tz.transition 1997, 3, :o5, 859676400
          tz.transition 1997, 10, :o6, 877820400
          tz.transition 1998, 3, :o5, 891126000
          tz.transition 1998, 10, :o6, 909270000
          tz.transition 1999, 3, :o5, 922575600
          tz.transition 1999, 10, :o6, 941324400
          tz.transition 2000, 3, :o5, 954025200
          tz.transition 2000, 10, :o6, 972774000
          tz.transition 2001, 3, :o5, 985474800
          tz.transition 2001, 10, :o6, 1004223600
          tz.transition 2002, 3, :o5, 1017529200
          tz.transition 2002, 10, :o6, 1035673200
          tz.transition 2003, 3, :o5, 1048978800
          tz.transition 2003, 10, :o6, 1067122800
          tz.transition 2004, 3, :o5, 1080428400
          tz.transition 2004, 10, :o6, 1099177200
          tz.transition 2005, 3, :o5, 1111878000
          tz.transition 2005, 10, :o6, 1130626800
          tz.transition 2006, 3, :o5, 1143327600
          tz.transition 2006, 10, :o6, 1162076400
          tz.transition 2007, 3, :o5, 1174777200
          tz.transition 2007, 10, :o6, 1193526000
          tz.transition 2008, 3, :o5, 1206831600
          tz.transition 2008, 10, :o6, 1224975600
          tz.transition 2009, 3, :o5, 1238281200
          tz.transition 2009, 10, :o6, 1256425200
          tz.transition 2010, 3, :o5, 1269730800
          tz.transition 2010, 10, :o6, 1288479600
          tz.transition 2011, 3, :o10, 1301180400
        end
      end
    end
  end
end
