module TZInfo
  module Definitions
    module Asia
      module Aqtobe
        include TimezoneDefinition
        
        timezone 'Asia/Aqtobe' do |tz|
          tz.offset :o0, 13720, 0, :LMT
          tz.offset :o1, 14400, 0, :AKTT
          tz.offset :o2, 18000, 0, :AKTT
          tz.offset :o3, 18000, 3600, :AKTST
          tz.offset :o4, 21600, 0, :AKTT
          tz.offset :o5, 18000, 0, :AQTT
          tz.offset :o6, 18000, 3600, :AQTST
          
          tz.transition 1924, 5, :o1, 5235639857, 2160
          tz.transition 1930, 6, :o2, 7278445, 3
          tz.transition 1981, 3, :o3, 354913200
          tz.transition 1981, 9, :o4, 370720800
          tz.transition 1982, 3, :o3, 386445600
          tz.transition 1982, 9, :o2, 402256800
          tz.transition 1983, 3, :o3, 417985200
          tz.transition 1983, 9, :o2, 433792800
          tz.transition 1984, 3, :o3, 449607600
          tz.transition 1984, 9, :o2, 465339600
          tz.transition 1985, 3, :o3, 481064400
          tz.transition 1985, 9, :o2, 496789200
          tz.transition 1986, 3, :o3, 512514000
          tz.transition 1986, 9, :o2, 528238800
          tz.transition 1987, 3, :o3, 543963600
          tz.transition 1987, 9, :o2, 559688400
          tz.transition 1988, 3, :o3, 575413200
          tz.transition 1988, 9, :o2, 591138000
          tz.transition 1989, 3, :o3, 606862800
          tz.transition 1989, 9, :o2, 622587600
          tz.transition 1990, 3, :o3, 638312400
          tz.transition 1990, 9, :o2, 654642000
          tz.transition 1991, 12, :o5, 692823600
          tz.transition 1992, 3, :o6, 701805600
          tz.transition 1992, 9, :o5, 717526800
          tz.transition 1993, 3, :o6, 733266000
          tz.transition 1993, 9, :o5, 748990800
          tz.transition 1994, 3, :o6, 764715600
          tz.transition 1994, 9, :o5, 780440400
          tz.transition 1995, 3, :o6, 796165200
          tz.transition 1995, 9, :o5, 811890000
          tz.transition 1996, 3, :o6, 828219600
          tz.transition 1996, 10, :o5, 846363600
          tz.transition 1997, 3, :o6, 859669200
          tz.transition 1997, 10, :o5, 877813200
          tz.transition 1998, 3, :o6, 891118800
          tz.transition 1998, 10, :o5, 909262800
          tz.transition 1999, 3, :o6, 922568400
          tz.transition 1999, 10, :o5, 941317200
          tz.transition 2000, 3, :o6, 954018000
          tz.transition 2000, 10, :o5, 972766800
          tz.transition 2001, 3, :o6, 985467600
          tz.transition 2001, 10, :o5, 1004216400
          tz.transition 2002, 3, :o6, 1017522000
          tz.transition 2002, 10, :o5, 1035666000
          tz.transition 2003, 3, :o6, 1048971600
          tz.transition 2003, 10, :o5, 1067115600
          tz.transition 2004, 3, :o6, 1080421200
          tz.transition 2004, 10, :o5, 1099170000
        end
      end
    end
  end
end
